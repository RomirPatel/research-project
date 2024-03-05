(()=>{"use strict";var e={496:e=>{e.exports=require("vscode")},81:e=>{e.exports=require("child_process")},147:e=>{e.exports=require("fs")},17:e=>{e.exports=require("path")}},t={};function s(o){var r=t[o];if(void 0!==r)return r.exports;var i=t[o]={exports:{}};return e[o](i,i.exports,s),i.exports}var o={};(()=>{var e=o;Object.defineProperty(e,"__esModule",{value:!0}),e.deactivate=e.activate=void 0;const t=s(17),r=s(147),i=s(81),a=s(496);function n(e){return new Promise(((t,s)=>{r.exists(e,(e=>{t(e)}))}))}const c=["build","compile","watch"];function d(e){for(const t of c)if(-1!==e.indexOf(t))return!0;return!1}const u=["test"];function h(e){for(const t of u)if(-1!==e.indexOf(t))return!0;return!1}let p,l;function k(){return p||(p=a.window.createOutputChannel("Jake Auto Detection")),p}function f(){a.window.showWarningMessage(a.l10n.t("Problem finding jake tasks. See the output for more information."),a.l10n.t("Go to output")).then((()=>{k().show(!0)}))}async function w(e){let s;const o=process.platform;return s="win32"===o&&await n(t.join(e,"node_modules",".bin","jake.cmd"))?t.join(".","node_modules",".bin","jake.cmd"):"linux"!==o&&"darwin"!==o||!await n(t.join(e,"node_modules",".bin","jake"))?"jake":t.join(".","node_modules",".bin","jake"),s}class v{constructor(e,t){this._workspaceFolder=e,this._jakeCommand=t}get workspaceFolder(){return this._workspaceFolder}isEnabled(){return"on"===a.workspace.getConfiguration("jake",this._workspaceFolder.uri).get("autoDetect")}start(){const e=t.join(this._workspaceFolder.uri.fsPath,"{node_modules,Jakefile,Jakefile.js}");this.fileWatcher=a.workspace.createFileSystemWatcher(e),this.fileWatcher.onDidChange((()=>this.promise=void 0)),this.fileWatcher.onDidCreate((()=>this.promise=void 0)),this.fileWatcher.onDidDelete((()=>this.promise=void 0))}async getTasks(){return this.isEnabled()?(this.promise||(this.promise=this.computeTasks()),this.promise):[]}async getTask(e){const t=e.definition.task;if(t){const s=e.definition,o={cwd:this.workspaceFolder.uri.fsPath};return new a.Task(s,this.workspaceFolder,t,"jake",new a.ShellExecution(await this._jakeCommand,[t],o))}}async computeTasks(){const e="file"===this._workspaceFolder.uri.scheme?this._workspaceFolder.uri.fsPath:void 0,s=[];if(!e)return s;let o=t.join(e,"Jakefile");if(!await n(o)&&(o=t.join(e,"Jakefile.js"),!await n(o)))return s;const r=`${await this._jakeCommand} --tasks`;try{const{stdout:t,stderr:s}=await(c=r,u={cwd:e},new Promise(((e,t)=>{i.exec(c,u,((s,o,r)=>{s&&t({error:s,stdout:o,stderr:r}),e({stdout:o,stderr:r})}))})));s&&(k().appendLine(s),f());const o=[];if(t){const e=t.split(/\r{0,1}\n/);for(const t of e){if(0===t.length)continue;const e=/^jake\s+([^\s]+)\s/g.exec(t);if(e&&2===e.length){const s=e[1],r={type:"jake",task:s},i={cwd:this.workspaceFolder.uri.fsPath},n=new a.Task(r,s,"jake",new a.ShellExecution(`${await this._jakeCommand} ${s}`,i));o.push(n);const c=t.toLowerCase();d(c)?n.group=a.TaskGroup.Build:h(c)&&(n.group=a.TaskGroup.Test)}}}return o}catch(e){const t=k();return e.stderr&&t.appendLine(e.stderr),e.stdout&&t.appendLine(e.stdout),t.appendLine(a.l10n.t("Auto detecting Jake for folder {0} failed with error: {1}', this.workspaceFolder.name, err.error ? err.error.toString() : 'unknown")),f(),s}var c,u}dispose(){this.promise=void 0,this.fileWatcher&&this.fileWatcher.dispose()}}class g{constructor(){this.detectors=new Map}start(){const e=a.workspace.workspaceFolders;e&&this.updateWorkspaceFolders(e,[]),a.workspace.onDidChangeWorkspaceFolders((e=>this.updateWorkspaceFolders(e.added,e.removed))),a.workspace.onDidChangeConfiguration(this.updateConfiguration,this)}dispose(){this.taskProvider&&(this.taskProvider.dispose(),this.taskProvider=void 0),this.detectors.clear()}updateWorkspaceFolders(e,t){for(const e of t){const t=this.detectors.get(e.uri.toString());t&&(t.dispose(),this.detectors.delete(e.uri.toString()))}for(const t of e){const e=new v(t,w(t.uri.fsPath));this.detectors.set(t.uri.toString(),e),e.isEnabled()&&e.start()}this.updateProvider()}updateConfiguration(){for(const e of this.detectors.values())e.dispose(),this.detectors.delete(e.workspaceFolder.uri.toString());const e=a.workspace.workspaceFolders;if(e)for(const t of e)if(!this.detectors.has(t.uri.toString())){const e=new v(t,w(t.uri.fsPath));this.detectors.set(t.uri.toString(),e),e.isEnabled()&&e.start()}this.updateProvider()}updateProvider(){if(!this.taskProvider&&this.detectors.size>0){const e=this;this.taskProvider=a.tasks.registerTaskProvider("jake",{provideTasks:()=>e.getTasks(),resolveTask:t=>e.getTask(t)})}else this.taskProvider&&0===this.detectors.size&&(this.taskProvider.dispose(),this.taskProvider=void 0)}getTasks(){return this.computeTasks()}computeTasks(){if(0===this.detectors.size)return Promise.resolve([]);if(1===this.detectors.size)return this.detectors.values().next().value.getTasks();{const e=[];for(const t of this.detectors.values())e.push(t.getTasks().then((e=>e),(()=>[])));return Promise.all(e).then((e=>{const t=[];for(const s of e)s&&s.length>0&&t.push(...s);return t}))}}async getTask(e){if(0!==this.detectors.size){if(1===this.detectors.size)return this.detectors.values().next().value.getTask(e);if(e.scope!==a.TaskScope.Workspace&&e.scope!==a.TaskScope.Global&&e.scope){const t=this.detectors.get(e.scope.uri.toString());if(t)return t.getTask(e)}}}}e.activate=function(e){l=new g,l.start()},e.deactivate=function(){l.dispose()}})();var r=exports;for(var i in o)r[i]=o[i];o.__esModule&&Object.defineProperty(r,"__esModule",{value:!0})})();
//# sourceMappingURL=https://ticino.blob.core.windows.net/sourcemaps/019f4d1419fbc8219a181fab7892ebccf7ee29a2/extensions/jake/dist/main.js.map