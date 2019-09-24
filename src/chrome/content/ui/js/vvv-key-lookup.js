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

Components.utils.import("resource://gre/modules/Services.jsm");

//TODO: delete
const nsIX509CertDB = Components.interfaces.nsIX509CertDB;
const nsX509CertDBContractID = "@mozilla.org/security/x509certdb;1";
const nsIX509Cert = Components.interfaces.nsIX509Cert;

/*
 * regular expression for valid email addresses (official RFC 5322 regex).
 */
const EMAIL_PATTERN = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
var tlds = ['AC', 'AD', 'AE', 'AERO', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR', 'ARPA', 'AS', 'ASIA', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BIZ', 'BJ', 'BM', 'BN', 'BO', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CAT', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'COM', 'COOP', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EDU', 'EE', 'EG', 'ER', 'ES', 'ET', 'EU', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GOV', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'INFO', 'INT', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JOBS', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MG', 'MH', 'MIL', 'MK', 'ML', 'MM', 'MN', 'MO', 'MOBI', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MUSEUM', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NAME', 'NC', 'NE', 'NET', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'ORG', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'POST', 'PR', 'PRO', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'ST', 'SU', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TEL', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TP', 'TR', 'TRAVEL', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UK', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'XN', 'XXX', 'YE', 'YT', 'ZA', 'ZM', 'ZW'];

var pgpEncryption = false;
var smimeEncryption = false;
var enigBtn = false;

var recipients = [];
var recipientsFromAddressFields = [];
var sender = "";


function sendToIframe(data) {
	var iframeEvent = new CustomEvent('vvv', {detail: data});
	document.getElementById("iframe-vvv").contentDocument.dispatchEvent(iframeEvent);
}


function checkRecipientsAddresses() {

	recipientsFromAddressFields = [];

	var win = Services.wm.getMostRecentWindow("msgcompose");
	composeFields = {};
	win.Recipients2CompFields(composeFields);
	extractEMailAddresses(composeFields.to);
	extractEMailAddresses(composeFields.cc);
	extractEMailAddresses(composeFields.bcc);
	//Application.console.log("[checkRecipientsAddresses] composeFields.to: "+composeFields.to);
	//Application.console.log("[checkRecipientsAddresses] recipientsFromAddressFields: "+recipientsFromAddressFields);

	/*
	 * Das Array recipients soll spaeter nicht nur die E-Mail-Adressen enthalten, sondern Objekte,
	 * die auch die gefundenen Schluessel enthalten.
	 *
	 * Um nicht bei jedem Tastendruck (d.h. jeder Aenderung im Adressfeld) eine komplette Schluesselsuche
	 * fuer alle E-Mail-Adressen zu starten, werden zuerst alle Objekte in recipients, die immernoch
	 * in recipientsFromAddressFields enthalten sind, in das temporaere Array geschrieben.
	 * Danach werden die neu hinzugekommenen E-Mail-Adressen ermittelt und nur fuer diese wird die Schluesselsuche
	 * gestartet und anschließend dem temporaeren Array hinzugefuegt.
	 */
	if (recipientsFromAddressFields.length > 0) {
		var tempList = [];
		if (recipients.length > 0) {
			for (let i=0; i<recipients.length; i++) {
				if ($.inArray(recipients[i], recipientsFromAddressFields) > -1) {
					tempList[tempList.length] = recipients[i];
				}
			}
		}
		for (let i=0; i<recipientsFromAddressFields.length; i++) {
			if ($.inArray(recipientsFromAddressFields[i], recipients) == -1) {
				tempList[tempList.length] = recipientsFromAddressFields[i];
				/*
				 * TODO: Fuer die E-Mail-Adresse recipientsFromAddressFields[i] pruefen,
				 * ob Schluessel im Cache vorhanden ist. Wenn ja: diesen Schluessel verwenden,
				 * wenn nein: DNSSEC-Abfrage/Schluesselsuche auf KeyServer. Gefundene Schluessel
				 * im Cache speichern und der tempList hinzufuegen..
				 */


			}
		}
		recipients = tempList;
	} else {
		recipients = [];
	}

	Application.console.log("[checkRecipientsAddresses] recipients: "+recipients);
}

function checkSenderAddress() {
	/*
	 * check if encryption is turned on/off after changing the sender account
	 * because the new sender account may have other default settings.
	 */
	if (isPGPEncryptionEnabled() || isSMIMEEncryptionEnabled()) {
		sender = document.getElementById("msgIdentity").description;
		//TODO:
		//checkRecipientsAddresses();
	}
	showVVVPanel();
}

/*
 * extracts all valid email addresses from the input string
 * and puts them in the global array 'recipientsFromAddressFields'.
 */
function extractEMailAddresses(input) {
	if (input.length > 0) {
		var addresses = input.split(",");

		for (let k=0; k<addresses.length; k++) {
			var res = addresses[k].trim();
			var ltIndex = res.indexOf("<");
			if (ltIndex >= 0) {
				res = res.substring(ltIndex+1, res.length);
			}
			var gtIndex = res.indexOf(">");
			if (gtIndex >= 0) {
				res = res.substring(0, gtIndex);
			}

			let match = EMAIL_PATTERN.exec(res);
			if (match) {
				//Application.console.log("[extractEMailAddresses] match");
				var tld = res.substring(res.lastIndexOf('.') + 1);
				Application.console.log("TLD: " + tld);
				if(tlds.indexOf(tld.toUpperCase()) > -1) {
					recipientsFromAddressFields[recipientsFromAddressFields.length] = res;
				}
			}
		}
	}
}

function isPGPEncryptionEnabled() {
	//var enigmailEncryptBtn = document.getElementById("button-enigmail-encrypt");
	var enigmailEncryptBtn = document.getElementById("button-enigmail-encrypt");
	var enigmailEncryptPgpMime = document.getElementById("enigmail_compose_pgpmime_item");
	var enigmailEncryptPgpInline = document.getElementById("enigmail_compose_inline_item");
	if (enigmailEncryptBtn) {

		let attr = enigmailEncryptBtn.getAttribute("checked");
		//TODO:delete
		Application.console.log("EnigButton: " + attr);
		if (attr == "true"/* && (enigmailEncryptPgpMime.getAttribute("checked") == "true" || enigmailEncryptPgpInline.getAttribute("checked") == "true")*/) {
			Application.console.log("[isPGPEncryptionEnabled] Enigmail encryption: ON");
			pgpEncryption = true;
			return true;
			//showVVVPanel();
		} else {
			Application.console.log("[isPGPEncryptionEnabled] Enigmail encryption: OFF");
			pgpEncryption = false;
			return false;
			//showVVVPanel();
		}
	}
}

function isSMIMEEncryptionEnabled() {
	//let encryptOn = gMsgCompose.compFields.securityInfo.QueryInterface(Components.interfaces.nsIMsgSMIMECompFields).requireEncryptMessage;
	//Application.console.log("[isSMIMEEncryptionEnabled]encryptOn: "+encryptOn);
	/*
	var smimeEncryptBtn = document.getElementById("menu_securityEncryptRequire2");
	let attr = smimeEncryptBtn.getAttribute("checked");
	Application.console.log("[isSMIMEEncryptionEnabled] S/MIME attr: "+attr);
	if (attr == "true") {
		Application.console.log("[isSMIMEEncryptionEnabled] S/MIME encryption: ON");
		smimeEncryption = true;
		return true;
		//showVVVPanel();
	} else {
		Application.console.log("[isSMIMEEncryptionEnabled] S/MIME encryption: OFF");
		smimeEncryption = false;
		return false;
		//showVVVPanel();
	}
	*/
	var enigmailEncryptBtn = document.getElementById("button-enigmail-encrypt");
	//var enigmailEncryptBtn = document.getElementById("enigmail_compose_encrypt_item");
	var enigmailEncryptSmime = document.getElementById("enigmail_compose_smime_item");
	if (enigmailEncryptBtn) {

		let attr = enigmailEncryptBtn.getAttribute("checked");
		//TODO:delete
		Application.console.log("EnigButton: " + attr);
		if (attr == "true"/* && enigmailEncryptSmime.getAttribute("checked") == "true"*/) {
			Application.console.log("[isSMIMEEncryptionEnabled] Enigmail encryption: ON");
			smimeEncryption = true;
			return true;
			//showVVVPanel();
		} else {
			Application.console.log("[isSMIMEEncryptionEnabled] Enigmail encryption: OFF");
			smimeEncryption = false;
			return false;
			//showVVVPanel();
		}
	}
}

function showVVVPanel() {
	pgpEncryption = isPGPEncryptionEnabled();
	var iframeElm = document.getElementById("iframe-vvv");
	var bodyElm = iframeElm.contentDocument.getElementById("vvv-iframe-body");
	if (pgpEncryption === true || smimeEncryption === true) {
		var data = {};
		data.action = "render";
		data.template = "iframe-key-table";
		data.gMsgCompose = gMsgCompose;
		data.composerDocument = document;

		data.data = {};
		if(sender !== "") {
			data.data.sender = {};
			data.data.sender.address = sender;
		}
		else
		{
			checkSenderAddress();
			data.data.sender = {};
			data.data.sender.address = sender;
		}
		data.data.recipients = [];
		for(var i=0; i<recipients.length; i++) {
			data.data.recipients[i] = {};
			data.data.recipients[i].address = recipients[i];
		}
		sendToIframe(data);
	}
	else {
		Application.console.log("\n\n\n render encryption-disabled\n\n\n");
		var data = {};
		data.action = "render";
		data.template = "iframe-encryption-disabled";
		data.gMsgCompose = gMsgCompose;
		data.composerDocument = document;

		data.data = {};
		data.data.recipients = recipients;
		sendToIframe(data);
	}
}



function addressOnChangeVVV() {
	checkRecipientsAddresses();
	showVVVPanel();
}

function senderOnChangeVVV() {
	checkSenderAddress();
	showVVVPanel();
}

function enigmailEncryptOnCommandVVV() {
	isPGPEncryptionEnabled();
	showVVVPanel();
	if (pgpEncryption === true || smimeEncryption === true) {
		checkSenderAddress();
		checkRecipientsAddresses();
	}
}

function smimeEncryptionOnSelectVVV() {
	isSMIMEEncryptionEnabled();
	showVVVPanel();
	if (pgpEncryption === true || smimeEncryption === true) {
		checkSenderAddress();
		checkRecipientsAddresses();
	}
}

var intervalTimer;

window.addEventListener("load",
	function _vvv_composeStartup(event) {

		checkSenderAddress();
		showVVVPanel();
		if (isPGPEncryptionEnabled() || isSMIMEEncryptionEnabled()) {
			Application.console.log("\n\ncheck sender address\n\n");
			//TODO: delete next line?
			checkSenderAddress();
			checkRecipientsAddresses();
		}

		var adrCol = document.getElementById("addressCol2#1"); // recipients field
		if (adrCol) {
			let attr = adrCol.getAttribute("oninput");
			adrCol.setAttribute("oninput", attr + "; addressOnChangeVVV();");
			adrCol.setAttribute("onblur", attr + "; addressOnChangeVVV();");
		}
		var adrCol2 = document.getElementById("addressCol2#2"); // recipients field
		if (adrCol2) {
			let attr2 = adrCol2.getAttribute("oninput");
			adrCol2.setAttribute("oninput", attr2 + "; addressOnChangeVVV();");
			adrCol2.setAttribute("onblur", attr2 + "; addressOnChangeVVV();");
		}
		var adrCol3 = document.getElementById("addressCol2#3"); // recipients field
		if (adrCol3) {
			let attr3 = adrCol3.getAttribute("oninput");
			adrCol3.setAttribute("oninput", attr3 + "; addressOnChangeVVV();");
			adrCol3.setAttribute("onblur", attr3 + "; addressOnChangeVVV();");
		}
		var senderCol = document.getElementById("msgIdentity");
		if (senderCol) {
			let attr = senderCol.getAttribute("onselect");
			senderCol.setAttribute("onselect", attr + "; senderOnChangeVVV();");
		}

		/*
		 * add event handler to smime button in order to
		 * know if S/MIME encryption is turned on or off.
		 */
		var smimeEncryptBtn = document.getElementById("menu_securityEncryptRequire2");
		if (smimeEncryptBtn) {
			let attr = smimeEncryptBtn.getAttribute("oncommand");
			smimeEncryptBtn.setAttribute("oncommand", attr + "; smimeEncryptionOnSelectVVV();");
		} else {
			Application.console.log("[vvv-key-lookup] Button 'menu_securityEncryptRequire2' not found.");
		}

		/*
		 * add events for enigmail buttons
		 */
		var smimeEncryptEBtn = document.getElementById("enigmail_compose_encrypt_item");
 		if (smimeEncryptEBtn) {
 			let attr = smimeEncryptEBtn.getAttribute("oncommand");
			let attr2 = smimeEncryptEBtn.getAttribute("onchange");
 			smimeEncryptEBtn.setAttribute("oncommand", attr + "; addressOnChangeVVV();");
			smimeEncryptEBtn.setAttribute("onchange", attr2 + "; addressOnChangeVVV();");
			//smimeEncryptBtn.setAttribute("onchange", attr2 + "; enigmailEncryptOnCommandVVV(); addressOnChangeVVV();");
			//smimeEncryptBtn.setAttribute("onchange", attr + "; smimeEncryptionOnSelectVVV();");
 		} else {
 			Application.console.log("[vvv-key-lookup] Button 'menu_securityEncryptRequire2' not found.");
 		}


		document.addEventListener("vvv-mail", childEventHandler, false);
	  setTimeout(function(){
			document.getElementById("addressCol2#1").focus();
			document.getElementById("addressCol2#1").blur();
			document.getElementById("addressCol2#1").focus();
		},	1000);


		setInterval(function(){
			var enigmailEncryptBtn = document.getElementById("button-enigmail-encrypt");
			if (enigmailEncryptBtn) {
				let attr = enigmailEncryptBtn.getAttribute("checked");

				if (attr == "true" && enigBtn === false) {
					enigBtn = true;
					Application.console.log("[isPGPEncryptionEnabled] Enigmail encryption: ON");
					pgpEncryption = true;
					addressOnChangeVVV();
					//showVVVPanel();
				} else if (attr == "" && enigBtn === true){
					enigBtn = false;
					Application.console.log("[isPGPEncryptionEnabled] Enigmail encryption: OFF");
					pgpEncryption = false;
					addressOnChangeVVV();
					//return false;
					//showVVVPanel();
				}
			}
		}, 1000);

	},
	false);

var childEventHandler = function (e) {
	addressOnChangeVVV();
};

/*
 * Accessing the main window from compose window:
 *
 *	var wMediator = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
 *	var mainWindow = wMediator.getMostRecentWindow("mail:3pane");
 *	Application.console.log("[addressOnChangeVVV] mainWindow: "+mainWindow);
 *	Application.console.log("[addressOnChangeVVV] mainWindow.hallo: "+mainWindow.hallo);
 */



/*addEventListener("compose-send-message", function (event) {
	openKeylookupDialog(event);
}, true);*/

// window.setInterval(function(e) { check_addrs(); }, 5000);

/*function openKeylookupDialog(event) {

	let enigmailEncryptButton = $("#button-enigmail-encrypt");
	if (enigmailEncryptButton != null) {
		let attr = enigmailEncryptButton.attr('checked');
		if (typeof attr !== typeof undefined && attr !== false) {
			Application.console.log("enigmail encrpyt button is checked!");
		}
	}

	let smimeEncryptButton = document.getElementById("menu_securityEncryptRequire2");
	Application.console.log("smimeEncryptButton: "+smimeEncryptButton);

	if (smimeEncryptButton.hasAttribute('checked')) {
		Application.console.log("smime encrpyt button has 'checked' attribute! ");
		// TODO: open dialog...
	} else {
		Application.console.log("smime encrpyt button has no 'checked' attribute!");
	}


	window.openDialog("chrome://vvv-addon/content/ui/key-lookup-dialog.html", "Key lookup", "centerscreen,all,modal", document);

	event.preventDefault();
    return false;
}*/
