/*
Keys4All Thunderbird-Addon
Designed and developed by
Fraunhofer Institute for Secure Information Technology SIT
<https://www.sit.fraunhofer.de>
(C) Copyright FhG SIT, 2018

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

var MWTool = {
		clickHandlerRegEx: new RegExp("^chrome://vvv-addon/content/"),
		openTab: function(chromePath) {
			Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator).getMostRecentWindow("mail:3pane").document.getElementById("tabmail").openTab("chromeTab", {chromePage: chromePath, clickHandler: "specialTabs.siteClickHandler(event, MWTool.clickHandlerRegEx);"});
		}
};

var vvv = (function () {

	var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
	var Application = Cc["@mozilla.org/steel/application;1"].getService(Ci.steelIApplication);

	Cu.import('resource://gre/modules/Services.jsm');
	Cu.import("resource://gre/modules/NetUtil.jsm");
	Cu.import("resource://gre/modules/ctypes.jsm");

	window.addEventListener("load", function () {
		//TODO: next line necessary?
		window.MWTool = MWTool;
		document.getElementById("button-vvv").onclick = function () {
			MWTool.openTab("chrome://vvv-addon/content/ui/index.html");
		};
		//TODO: delete MWTool.openTab("chrome://vvv-addon/content/ui/vvv-key-updater.html");
		console.log("added event listener");
	});
	//window.addEventListener("unload", unload);
	Application.console.log('VVV-Addon started');

} ());
