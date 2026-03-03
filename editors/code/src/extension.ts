import * as vscode from "vscode";
import { execSync } from "child_process";

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("rnicro.pickProcess", pickProcess)
  );

  context.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider(
      "rnicro",
      new RnicroConfigurationProvider()
    )
  );

  context.subscriptions.push(
    vscode.debug.registerDebugAdapterDescriptorFactory(
      "rnicro",
      new RnicroDebugAdapterFactory()
    )
  );
}

export function deactivate(): void {}

class RnicroDebugAdapterFactory
  implements vscode.DebugAdapterDescriptorFactory
{
  createDebugAdapterDescriptor(
    _session: vscode.DebugSession,
    _executable: vscode.DebugAdapterExecutable | undefined
  ): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
    const config = vscode.workspace.getConfiguration("rnicro");
    const rnicroPath = config.get<string>("path", "rnicro");
    return new vscode.DebugAdapterExecutable(rnicroPath, ["--dap"]);
  }
}

class RnicroConfigurationProvider
  implements vscode.DebugConfigurationProvider
{
  provideDebugConfigurations(
    _folder: vscode.WorkspaceFolder | undefined,
    _token?: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.DebugConfiguration[]> {
    return [
      {
        type: "rnicro",
        request: "launch",
        name: "rnicro: Launch",
        program:
          "${workspaceFolder}/target/debug/${workspaceFolderBasename}",
        args: [],
        stopOnEntry: true,
      },
    ];
  }

  resolveDebugConfiguration(
    _folder: vscode.WorkspaceFolder | undefined,
    config: vscode.DebugConfiguration,
    _token?: vscode.CancellationToken
  ): vscode.ProviderResult<vscode.DebugConfiguration> {
    if (!config.type && !config.request && !config.name) {
      config.type = "rnicro";
      config.request = "launch";
      config.name = "rnicro: Launch";
      config.program =
        "${workspaceFolder}/target/debug/${workspaceFolderBasename}";
      config.stopOnEntry = true;
    }

    if (config.request === "launch") {
      if (!config.program) {
        vscode.window.showErrorMessage(
          'rnicro: "program" is required in launch configuration.'
        );
        return undefined;
      }
    }

    if (config.request === "attach") {
      if (config.pid && typeof config.pid === "string") {
        const parsed = parseInt(config.pid, 10);
        if (isNaN(parsed)) {
          vscode.window.showErrorMessage(
            `rnicro: Invalid PID "${config.pid}".`
          );
          return undefined;
        }
        config.pid = parsed;
      }
    }

    return config;
  }
}

interface ProcessItem extends vscode.QuickPickItem {
  pid: string;
}

async function pickProcess(): Promise<string | undefined> {
  let processes: ProcessItem[];
  try {
    const output = execSync("ps -axo pid=,comm= --sort=-pid", {
      encoding: "utf8",
      timeout: 5000,
    });
    processes = output
      .trim()
      .split("\n")
      .filter((line: string) => line.trim().length > 0)
      .map((line: string) => {
        const trimmed = line.trim();
        const spaceIdx = trimmed.indexOf(" ");
        const pid = trimmed.substring(0, spaceIdx).trim();
        const name = trimmed.substring(spaceIdx).trim();
        return { label: pid, description: name, pid } as ProcessItem;
      });
  } catch {
    vscode.window.showErrorMessage(
      "rnicro: Failed to list processes."
    );
    return undefined;
  }

  const picked = await vscode.window.showQuickPick(processes, {
    placeHolder: "Select a process to attach to",
    matchOnDescription: true,
  });

  return picked?.pid;
}
