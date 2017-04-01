/*---------------------------------------------------------
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *--------------------------------------------------------*/

'use strict';

import * as vscode from 'vscode';

const initialConfigurations = {
	version: '0.1.0',
	configurations: [
		{
			type: "wdd",
			request: "launch",
            use64bitDebugger: false,
			name: 'Wdd:Laucnh Replay',
			program: "${workspaceRoot}/${command:AskForProgramName}",
			stopOnEntry: true
		}
	]
};

export function activate(context: vscode.ExtensionContext) {

	context.subscriptions.push(vscode.commands.registerCommand('extension.wdd-vscode.getProgramName', config => {
		return vscode.window.showInputBox({
			placeHolder: "Please enter the name of a exe file in the workspace folder",
			value: "program.exe"
		});
	}));

	context.subscriptions.push(vscode.commands.registerCommand('extension.wdd-vscode.provideInitialConfigurations', () => {
		return [
			'// Use IntelliSense to learn about possible WDD debugger attributes.',
			'// Hover to view descriptions of existing attributes.',
			JSON.stringify(initialConfigurations, null, '\t')
		].join('\n');
	}));
}

export function deactivate() {
	// nothing to do
}
