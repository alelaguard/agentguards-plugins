import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { AgentGuardsClient, isAgentGuardsKey } from "./core/api";

const SECRET = "agentguards.apiKey";
const SIGNUP_URL = "https://agentguards.co/sign-up";
const KEYS_URL = "https://agentguards.co/dashboard/keys";

/** The key the AgentGuards installer saved (~/.agentguards/credentials.json), if valid. */
export async function installerKey(): Promise<string | undefined> {
  try {
    const p = path.join(os.homedir(), ".agentguards", "credentials.json");
    const k = JSON.parse(await fs.readFile(p, "utf8"))?.api_key;
    const key = typeof k === "string" ? k.trim() : undefined;
    return isAgentGuardsKey(key) ? key : undefined;
  } catch {
    return undefined;
  }
}

export class Auth {
  private readonly changed = new vscode.EventEmitter<boolean>();
  readonly onDidChange = this.changed.event;

  constructor(
    private readonly secrets: vscode.SecretStorage,
    private readonly client: () => AgentGuardsClient,
    private readonly log: (m: string) => void,
  ) {
    secrets.onDidChange(async (e) => {
      if (e.key === SECRET) this.changed.fire(await this.isSignedIn());
    });
  }

  getKey(): Thenable<string | undefined> {
    return this.secrets.get(SECRET);
  }

  async isSignedIn(): Promise<boolean> {
    return isAgentGuardsKey(await this.getKey());
  }

  async signOut(): Promise<void> {
    await this.secrets.delete(SECRET);
  }

  private async store(key: string): Promise<void> {
    await this.secrets.store(SECRET, key);
    this.changed.fire(true);
  }

  /** Returns true when a key was stored. */
  async signIn(): Promise<boolean> {
    type Pick = vscode.QuickPickItem & { id: "installer" | "browser" | "paste" | "signup" };
    const items: Pick[] = [];
    if (await installerKey()) {
      items.push({
        id: "installer",
        label: "$(key) Use the key from the AgentGuards installer",
        detail: "Found in ~/.agentguards/credentials.json. Uses no extra key slot.",
      });
    }
    items.push(
      {
        id: "browser",
        label: "$(globe) Sign in with your browser",
        detail: "Approve this editor in the AgentGuards dashboard. Creates a new API key.",
      },
      { id: "paste", label: "$(clippy) Paste an API key", detail: "From Dashboard → API Keys." },
      { id: "signup", label: "$(person-add) Create a free account", detail: SIGNUP_URL },
    );
    const choice = await vscode.window.showQuickPick(items, {
      title: "Sign in to AgentGuards",
      ignoreFocusOut: true,
    });
    if (!choice) return false;

    if (choice.id === "signup") {
      await vscode.env.openExternal(vscode.Uri.parse(SIGNUP_URL));
      return false;
    }
    if (choice.id === "installer") {
      const key = await installerKey();
      if (!key) return false;
      await this.store(key);
      return true;
    }
    if (choice.id === "paste") {
      const key = await vscode.window.showInputBox({
        title: "AgentGuards API key",
        prompt: `Create one at ${KEYS_URL}`,
        password: true,
        ignoreFocusOut: true,
        validateInput: (v) =>
          isAgentGuardsKey(v.trim()) ? undefined : "An AgentGuards key starts with ag_",
      });
      if (!key) return false;
      await this.store(key.trim());
      return true;
    }
    return this.browserSignIn();
  }

  private async browserSignIn(): Promise<boolean> {
    const client = this.client();
    let code;
    try {
      code = await client.deviceCode(`vscode @ ${os.hostname()}`);
    } catch (err) {
      void vscode.window.showErrorMessage(`AgentGuards: ${(err as Error).message}`);
      return false;
    }
    const opened = await vscode.env.openExternal(vscode.Uri.parse(code.verification_uri_complete));
    if (!opened) {
      void vscode.window.showInformationMessage(
        `Open ${code.verification_uri} and enter the code ${code.user_code}.`,
      );
    }

    return vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `AgentGuards: approve this editor in your browser (code ${code.user_code})`,
        cancellable: true,
      },
      async (_progress, token) => {
        let interval = Math.max(1, code.interval) * 1000;
        const deadline = Date.now() + code.expires_in * 1000;
        while (!token.isCancellationRequested && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, interval));
          if (token.isCancellationRequested) return false;
          let res;
          try {
            res = await client.deviceToken(code.device_code);
          } catch (err) {
            this.log(`sign-in poll failed: ${(err as Error).message}`);
            continue;
          }
          if ("api_key" in res) {
            await this.store(res.api_key);
            void vscode.window.showInformationMessage("AgentGuards: signed in.");
            return true;
          }
          switch (res.error) {
            case "authorization_pending":
              continue;
            case "slow_down":
              interval += 5000;
              continue;
            case "access_denied":
              void vscode.window.showWarningMessage("AgentGuards: sign-in was denied.");
              return false;
            case "key_limit_reached":
              void vscode.window.showErrorMessage(
                "AgentGuards: your plan's API key limit is reached. Remove an unused key in the dashboard, or sign in with an existing key.",
              );
              return false;
            case "expired_token":
              break;
            default:
              this.log(`sign-in error: ${res.error}`);
              void vscode.window.showErrorMessage("AgentGuards: sign-in failed. Try again.");
              return false;
          }
          break;
        }
        if (!token.isCancellationRequested) {
          void vscode.window.showWarningMessage("AgentGuards: the sign-in code expired. Try again.");
        }
        return false;
      },
    );
  }
}
