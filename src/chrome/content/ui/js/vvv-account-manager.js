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
﻿Components.utils.import("resource://gre/modules/Services.jsm");

const nsIX509CertDB = Components.interfaces.nsIX509CertDB;
const nsX509CertDBContractID = "@mozilla.org/security/x509certdb;1";
const nsIX509Cert = Components.interfaces.nsIX509Cert;

/*
 * Hashtable: Key = email address, value = object{'smimeCert', 'smimeCertStatus', 'pgpKey', 'pgpKeyStatus'}
 *
 * smimeCertStatus / pgpKeyStatus: 0 = unpublished, 1 = publication in process, 2 = published
 */
var listEmailCertificates = {};

var numberPublishedKeys = 0;
var numberPublishedCertificates = 0;
var numberUnpublishedKeys = 0;
var numberUnpublishedCertificates = 0;

function numberOfAccounts() {
	var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                            .getService(Components.interfaces.nsIMsgAccountManager);
    var accounts = accMgr.accounts;

	return accounts.length;
}

function getEMailAdressesFromAccount(accountIndex) {
	var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                            .getService(Components.interfaces.nsIMsgAccountManager);
    var accounts = accMgr.accounts;

	if (accountIndex >= accounts.length) {
		return [];
	}
	var account = accounts.queryElementAt(accountIndex, Components.interfaces.nsIMsgAccount);
	var emailAddresses = [];
	for (var j= 0; j < account.identities.length; j++) {
		var identity = account.identities.queryElementAt(j, Components.interfaces.nsIMsgIdentity);
		emailAddresses.push(identity.email);
		// DEBUG ONLY:
		var certname = identity.getUnicharAttribute("encryption_cert_name");
		var email = identity.email;
		Application.console.log("E-Mail: "+email+", Certname: "+certname);

		var certdb = Components.classes[nsX509CertDBContractID].getService(nsIX509CertDB);
		if (!certdb) {
			Application.console.log("certdb is null");
		}
		cert = certdb.findEmailEncryptionCert(certname);
		if (cert != null) {
			Application.console.log("Certificate issuer: "+cert.issuerName);
			Application.console.log("Certificate subject: "+cert.subjectName);
			Application.console.log("Certificate sha256Fingerprint: "+cert.sha256Fingerprint);
			Application.console.log("Certificate sha1Fingerprint: "+cert.sha1Fingerprint);
			Application.console.log("Certificate tokenName: "+cert.tokenName);
			Application.console.log("Certificate serialNumber: "+cert.serialNumber);
			Application.console.log("Certificate displayName: "+cert.displayName);
			Application.console.log("Certificate validity: "+cert.validity);
			Application.console.log("Certificate validity not before: "+cert.validity.notBeforeLocalTime);
			Application.console.log("Certificate validity not after: "+cert.validity.notAfterLocalTime);
		}

	}
	return emailAddresses;
}

function getIdentitiesFromAccount(accountIndex) {
	var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                            .getService(Components.interfaces.nsIMsgAccountManager);
    var accounts = accMgr.accounts;

	if (accountIndex >= accounts.length) {
		return [];
	}
	var account = accounts.queryElementAt(accountIndex, Components.interfaces.nsIMsgAccount);
	var identities = [];
	for (var j= 0; j < account.identities.length; j++) {
		var identity = account.identities.queryElementAt(j, Components.interfaces.nsIMsgIdentity);
		if (identity.email.endsWith("keys4all-test.de")) {
			identities.push(identity);
		}
	}
	return identities;
}

function getSMimeEncryptionCertificate(identity) {
	if (identity == null) {
		return;
	}
	var certname = identity.getUnicharAttribute("encryption_cert_name");

	var certdb = Components.classes[nsX509CertDBContractID].getService(nsIX509CertDB);
	if (!certdb) {
		Application.console.log("certdb is null");
		return;
	}
	cert = certdb.findEmailEncryptionCert(certname);
	return cert;
}

function getPGPEncryptionCertificates(identity) {
	if (identity == null) {
		return;
	}
	var pgpKeys = KeyManager.getPublicKeys(identity.email);
	if (pgpKeys.length == 0) {
		return;
	}
	Application.console.log("Number of PGP keys: "+pgpKeys.length);
	return pgpKeys;
}


function generateAccountList() {
	var number = numberOfAccounts();

	for (var i=0; i<number; i++) {
		var identities = getIdentitiesFromAccount(i);
		Application.console.log("Number of Identities: "+identities.length);
		if (identities.length > 0) {
			for (var j=0; j<identities.length; j++) {
				smimeCert = getSMimeEncryptionCertificate(identities[j]);
				Application.console.log("smime cert: "+smimeCert);
				pgpKeys = getPGPEncryptionCertificates(identities[j]);

				certContainer = new Object();
				certContainer.smimeCert = smimeCert;
				certContainer.smimeCertStatus = 0;

				certContainer.pgpKeys = pgpKeys;
				certContainer.pgpKeyStatus = 0;
				certContainer.pgpKeySelected = 0;
				listEmailCertificates[identities[j].email] = [certContainer];

			}
		}
	}

	var smimeCounter = 0;
	var pgpCounter = 0;
	var emailAddresses = Object.keys(listEmailCertificates);
	Application.console.log("email addresses: "+emailAddresses);
	if (emailAddresses.length > 0) {
		Application.console.log("Number of listEmailCertificates: "+emailAddresses.length);
		for (var i=0; i<emailAddresses.length; i++) {
			var email = emailAddresses[i];
			var indexOfAt = email.indexOf("@");
			var domain = email.substring(indexOfAt+1);
			Application.console.log("email: "+email);
			certContainer = listEmailCertificates[email];
			if (certContainer == null || !certContainer) {
				Application.console.log("certContainer is null");
			}
			var smimeCert = certContainer[0].smimeCert;
			var pgpKey = null;
			if (certContainer[0].pgpKeys != null && certContainer[0].pgpKeys.length > 0) {
				pgpKey = certContainer[0].pgpKeys[0];
			}

			if (smimeCert != null) {
				Application.console.log("smime cert found. ");
				smimeCounter++;
				var keyEntryId = "key-entry-smime"+smimeCounter;
				var accordionId = "accordion-smime"+smimeCounter;
				var panelId = "panel-smime"+smimeCounter;
				var headingId = "heading-smime"+smimeCounter;
				var collapse1Id = "collapse1-smime"+smimeCounter;
				var collapse2Id = "collapse2-smime"+smimeCounter;
				var collapse3Id = "collapse3-smime"+smimeCounter;
				var infoId = "info-smime"+smimeCounter;
				var actionId = "action-smime"+smimeCounter;
				var privacyId = "privacy-smime"+smimeCounter;
				var commitEmailId = "commit-email-smime"+smimeCounter;
				var commitKeyId = "commit-key-smime"+smimeCounter;
				var submitId = "submit"+smimeCounter;
				var abortSMIMEModal = "abortSMIMEModal"+smimeCounter;
				var revokeSMIMEModal = "revokeSMIMEModal"+smimeCounter;
				var passwordFieldId = "passwordSMIME"+smimeCounter;
				var revocationId = "revocation-smime"+smimeCounter;
				var abortRevocationSMIMEModal = "abortRevocationSMIMEModal"+smimeCounter;

				var issuer = insertLineBreaks(smimeCert.issuerName);
				//var subject = smimeCert.subjectName;
				var subject = insertLineBreaks(smimeCert.subjectName);
				//var subject = cutString(smimeCert.subjectName);
				var fingerprint = "";
				if (smimeCert.sha256Fingerprint) {
					fingerprint = smimeCert.sha256Fingerprint;
				} else {
					fingerprint = smimeCert.sha1Fingerprint;
				}
				var originalFingerprint = fingerprint;
				fingerprint = fingerprint.replace(/:/g, ' ');
				var notBefore = smimeCert.validity.notBeforeLocalTime;
				var notAfter = smimeCert.validity.notAfterLocalTime;

				var serial = smimeCert.serialNumber;

				var context = {abortRevocationSMIMEModal: abortRevocationSMIMEModal, revocationId: revocationId, passwordFieldId: passwordFieldId, abortSMIMEModal: abortSMIMEModal, revokeSMIMEModal: revokeSMIMEModal, emailAddress: email, keyEntryId: keyEntryId, accordionId: accordionId, panelId: panelId, headingId: headingId, collapse1Id: collapse1Id, collapse2Id: collapse2Id, collapse3Id: collapse3Id, infoId: infoId, actionId: actionId, privacyId: privacyId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, issuer: issuer, subject: subject, fingerprint: fingerprint, originalFingerprint: originalFingerprint, notBefore: notBefore, notAfter: notAfter, serial: serial, domain: domain, submitId: submitId};
				var html = templateShowSMimeKey(context);
				if (isKeyPublished(email, "smime", originalFingerprint) === true) {
					$("#published-keys").append(html);
					$('#'+panelId).removeClass('panel-default');
					$('#'+panelId).addClass('panel-published');
					var iconSpanElm = $('#'+actionId).children().first();
					if (iconSpanElm.hasClass('glyphicon-plus')) {
						iconSpanElm.removeClass('glyphicon-plus');
						iconSpanElm.addClass('glyphicon-minus');
					}
					numberPublishedCertificates++;
					certContainer[0].smimeCertStatus = 2;
				} else {
					$("#unpublished-keys").append(html);
					numberUnpublishedCertificates++;
				}


			}

			if (pgpKey != null) {
				Application.console.log("pgp key found. ");
				pgpCounter++;
				var keyEntryId = "key-entry-pgp"+pgpCounter;
				var accordionId = "accordion-pgp"+pgpCounter;
				var panelId = "panel-pgp"+pgpCounter;
				var headingId = "heading-pgp"+pgpCounter;
				var collapse1Id = "collapse1-pgp"+pgpCounter;
				var collapse2Id = "collapse2-pgp"+pgpCounter;
				var collapse3Id = "collapse3-pgp"+pgpCounter;
				var infoId = "info-pgp"+pgpCounter;
				var actionId = "action-pgp"+pgpCounter;
				var privacyId = "privacy-pgp"+pgpCounter;
				var commitEmailId = "commit-email-pgp"+pgpCounter;
				var commitKeyId = "commit-key-pgp"+pgpCounter;
				var submitId = "submit"+pgpCounter;
				var abortPGPModal = "abortPGPModal"+pgpCounter;
				var revokePGPModal = "revokePGPModal"+pgpCounter;
				var passwordFieldId = "passwordPGP"+pgpCounter;
				var revocationId = "revocation-pgp"+pgpCounter;
				var abortRevocationPGPModal = "abortRevocationPGPModal"+pgpCounter;
				var selectOptionsId = "selectOptionsPGP"+pgpCounter+"-";
				var selectOptionsName = "selectOptionsPGP"+pgpCounter;
				var showHideId = "showHidePGP"+pgpCounter+"-";
				var badgeId = "badgePGP"+pgpCounter;
				var radioDivId = "radioDivPGP"+pgpCounter+"-";


				var key_id = pgpKey.primaryKey.getKeyId().toHex();
				key_id = key_id.substring(8);
				var fingerprint = pgpKey.primaryKey.getFingerprint();
				var originalFingerprint = fingerprint;
				fingerprint = fingerprint.replace(/:/g, ' ');
				var validUntil = pgpKey.getExpirationTime();
				var userids = pgpKey.getUserIds();
				var name = userids[0];
				var serial = '';
				var issuer = '';
				var subject = '';
				var notBefore = '';

				var pgpData = [];
				for (var k=0; k<certContainer[0].pgpKeys.length; k++) {
					var pgp = new Object();
					pgp.index = k;
					pgp.selectOptionsId = selectOptionsId;
					pgp.selectOptionsName = selectOptionsName;
					pgp.showHideId = showHideId;
					pgp.radioDivId = radioDivId;
					pgp.numberPGPKeys = certContainer[0].pgpKeys.length;

					var key_id = certContainer[0].pgpKeys[k].primaryKey.getKeyId().toHex();
					pgp.keyId = key_id.substring(8);
					var fingerprint = certContainer[0].pgpKeys[k].primaryKey.getFingerprint();
					var originalFingerprint = fingerprint;
					pgp.originalFingerprint = originalFingerprint;
					fingerprint = fingerprint.replace(/:/g, ' ');
					pgp.fingerprint = fingerprint;
					var validUntil = certContainer[0].pgpKeys[k].getExpirationTime();
					pgp.validUntil = validUntil;

					pgpData[k] = pgp;
				}

				var indexOfPublishedKey = isPGPKeyPublished(email, "pgp", pgpData);
				Application.console.log("indexOfPublishedKey: "+indexOfPublishedKey);
				if (indexOfPublishedKey >= 0) {
					var context = {abortRevocationPGPModal: abortRevocationPGPModal, revocationId: revocationId, passwordFieldId: passwordFieldId, abortPGPModal: abortPGPModal, revokePGPModal: revokePGPModal, emailAddress: email, keyEntryId: keyEntryId, accordionId: accordionId, panelId: panelId, headingId: headingId, collapse1Id: collapse1Id, collapse2Id: collapse2Id, collapse3Id: collapse3Id, infoId: infoId, actionId: actionId, privacyId: privacyId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, keyId: key_id, fingerprint: fingerprint, originalFingerprint: originalFingerprint, validUntil: validUntil, serial: serial, issuer: issuer, subject: subject, notBefore: notBefore, name: name, domain: domain, submitId: submitId, pgpData: pgpData, numberPGPKeys: certContainer[0].pgpKeys.length, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId};
					var html = templateShowPGPKey(context);

					$("#published-keys").append(html);
					$('#'+panelId).removeClass('panel-default');
					$('#'+panelId).addClass('panel-published');
					var iconSpanElm = $('#'+actionId).children().first();
					if (iconSpanElm.hasClass('glyphicon-plus')) {
						iconSpanElm.removeClass('glyphicon-plus');
						iconSpanElm.addClass('glyphicon-minus');
					}

					// hide unpublished keys and hide radio buttons
					for (var k=0; k<pgpData.length; k++) {
						if (k != indexOfPublishedKey) {
							$('#'+pgpData[k].showHideId+k).hide();
						}
						$('#'+pgpData[k].radioDivId+k).hide();
					}
					$('#'+selectOptionsId+indexOfPublishedKey).prop('checked', true);
					$('label[for='+selectOptionsId+indexOfPublishedKey+']').html("<span class='font-black-bold'>Dieser Schlüssel ist ausgewählt</span>");

					// hide badge
					$('#'+badgeId).css("visibility", "hidden");

					numberPublishedKeys++;
					certContainer[0].pgpKeyStatus = 2;
				} else {
					var context = {abortRevocationPGPModal: abortRevocationPGPModal, revocationId: revocationId, passwordFieldId: passwordFieldId, abortPGPModal: abortPGPModal, revokePGPModal: revokePGPModal, emailAddress: email, keyEntryId: keyEntryId, accordionId: accordionId, panelId: panelId, headingId: headingId, collapse1Id: collapse1Id, collapse2Id: collapse2Id, collapse3Id: collapse3Id, infoId: infoId, actionId: actionId, privacyId: privacyId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, keyId: key_id, fingerprint: fingerprint, originalFingerprint: originalFingerprint, validUntil: validUntil, serial: serial, issuer: issuer, subject: subject, notBefore: notBefore, name: name, domain: domain, submitId: submitId, pgpData: pgpData, numberPGPKeys: certContainer[0].pgpKeys.length, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId};
					var html = templateShowPGPKey(context);
					$("#unpublished-keys").append(html);
					numberUnpublishedKeys++;

					$('#'+selectOptionsId+"0").prop('checked', true);
					$('label[for='+selectOptionsId+'0]').html("<span class='font-black-bold'>Dieser Schlüssel ist ausgewählt</span>");
				}
			}
		}
	}

}

function showSelectKeysPage() {

	$('#nav-welcome').removeClass("link-keys4all");
	$('#nav-welcome').addClass("font-black");

	$('#nav-keymgmt').removeClass("font-black");
	$('#nav-keymgmt').addClass("link-keys4all");

	var context = {};
	var html = templateSelectKeys(context);
	$("#body").html(html);

	generateAccountList();

	showCountText();

}

function initKeyPublicationPanel(passwordFieldId, accordionId, keyEntryId, infoId, privacyId, commitEmailId, commitKeyId, email, keyId, serial, name, issuer, subject, validUntil, notBefore, fingerprint, originalFingerprint, collapse2Id, collapse3Id, panelId, actionId, domain, submitId, abortModalId, revokeModalId, abortRevocationModalId, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {
	Application.console.log("isPGP: "+isPGP);

	certContainer = listEmailCertificates[email];
	if (certContainer == null || !certContainer) {
		Application.console.log("certContainer is null");
	}

	//$('#'+actionId).prop("checked", true);

	if ((isPGP == 1 && certContainer[0].pgpKeyStatus == 0) || (isPGP == 0 && certContainer[0].smimeCertStatus == 0)) {
		// unpublished

		if (isPGP == 1) {
			certContainer[0].pgpKeyStatus = 1;
		} else {
			certContainer[0].smimeCertStatus = 1;
		}

		Application.console.log("disabled: "+$('#'+infoId).attr('disabled'));
		if ($('#'+infoId).attr('disabled') == 'disabled') {
			$('#'+infoId).removeAttr('disabled');
		} else {
			$('#'+infoId).attr('disabled', 'disabled');
		}

		var iconSpanElm = $('#'+infoId).children().first();
		if (iconSpanElm.hasClass('glyphicon-triangle-top')) {
			iconSpanElm.removeClass('glyphicon-triangle-top');
			iconSpanElm.addClass('glyphicon-triangle-bottom');
		}

		$('#'+privacyId).removeClass('list-group-item-success');
		$('#'+commitEmailId).removeClass('list-group-item-success');
		$('#'+commitKeyId).removeClass('list-group-item-success');

		$('#'+privacyId).removeClass('disabled');
		$('#'+commitEmailId).removeClass('disabled');
		$('#'+commitKeyId).removeClass('disabled');

		$('#'+commitEmailId).addClass('disabled');
		$('#'+commitKeyId).addClass('disabled');

		if(isPGP == 1) {

			/*
			 * get keyId, name, validUntil, fingerprint, originalFingerprint from selected PGP key
			 */
			for (var i=0; i<numberPGPKeys; i++) {
				if (($('#'+selectOptionsId+i).attr('checked') == 'checked') || ($('#'+selectOptionsId+i).prop('checked') == true)) {
					var value = $('#'+selectOptionsId+i).attr('value');
					Application.console.log("value = "+value);
					var pgpKey = certContainer[0].pgpKeys[value];
					keyId = pgpKey.primaryKey.getKeyId().toHex();
					keyId = keyId.substring(8);
					fingerprint = pgpKey.primaryKey.getFingerprint();
					originalFingerprint = fingerprint;
					fingerprint = fingerprint.replace(/:/g, ' ');
					validUntil = pgpKey.getExpirationTime();
					var userids = pgpKey.getUserIds();
					name = userids[0];
				}
			}

			var context = {passwordFieldId: passwordFieldId, accordionId: accordionId, abortModalId: abortModalId, keyEntryId: keyEntryId, emailAddress: email, keyId: keyId, name: name, validUntil: validUntil, fingerprint: fingerprint, originalFingerprint: originalFingerprint, privacyId: privacyId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, collapse2Id: collapse2Id, panelId: panelId, infoId: infoId, actionId: actionId, domain: domain, submitId: submitId, numberPGPKeys: numberPGPKeys, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId};
			$('#'+privacyId).html(templatePrivacyAgreementCollapsedPGP(context));
		} else {
			var context = {passwordFieldId: passwordFieldId, accordionId: accordionId, abortModalId: abortModalId, keyEntryId: keyEntryId, emailAddress: email, serial: serial, issuer: issuer, subject: subject, notBefore: notBefore, notAfter: validUntil, fingerprint: fingerprint, originalFingerprint: originalFingerprint, privacyId: privacyId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, collapse2Id: collapse2Id, panelId: panelId, infoId: infoId, actionId: actionId, domain: domain, submitId: submitId};
			$('#'+privacyId).html(templatePrivacyAgreementCollapsedSMime(context));
		}
		$('#'+commitEmailId).html(templateCommitEMailMin({}));
		$('#'+commitKeyId).html(templateCommitKeyMin({}));

		//$('#'+actionId).attr('type', 'button');

	} else if ((isPGP == 1 && certContainer[0].pgpKeyStatus == 1) || (isPGP == 0 && certContainer[0].smimeCertStatus == 1)) {

		// publication in progress
		$('#'+actionId).attr('data-toggle', 'modal');
		$('#'+actionId).attr('data-target', '#'+abortModalId);

		var iconSpanElm = $('#'+infoId).children().first();
		if (iconSpanElm.hasClass('glyphicon-triangle-top')) {
			iconSpanElm.removeClass('glyphicon-triangle-top');
			iconSpanElm.addClass('glyphicon-triangle-bottom');
		}

	} else if ((isPGP == 1 && certContainer[0].pgpKeyStatus == 2) || (isPGP == 0 && certContainer[0].smimeCertStatus == 2)) {
		// published

		if ($('#'+actionId).attr('data-target') == '#'+collapse3Id) {
			$('#'+actionId).attr('data-toggle', 'modal');
			$('#'+actionId).attr('data-target', '#'+abortRevocationModalId);
		} else {
			$('#'+actionId).attr('data-toggle', 'modal');
			$('#'+actionId).attr('data-target', '#'+revokeModalId);
		}


		/*
		if (isPGP == 1) {
			$('#'+actionId).attr('data-toggle', 'modal');
			$('#'+actionId).attr('data-target', '#'+revokeModalId);
		} else {
			$('#'+actionId).attr('data-toggle', 'modal');
			$('#'+actionId).attr('data-target', '#'+revokeModalId);
		}*/
	}
}

function agreePrivacy(passwordFieldId, keyEntryId, privacyId, commitEmailId, commitKeyId, collapse2Id, panelId, infoId, actionId, emailAddress, originalFingerprint, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {
	$('#'+privacyId).addClass('list-group-item-keys4all');
	$('#'+privacyId).html(templatePrivacyAgreementMin({}));

	$('#'+commitEmailId).removeClass('disabled');
	var context = {passwordFieldId: passwordFieldId, keyEntryId: keyEntryId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, collapse2Id: collapse2Id, panelId: panelId, infoId: infoId, actionId: actionId, emailAddress: emailAddress, originalFingerprint: originalFingerprint, numberPGPKeys: numberPGPKeys, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId, isPGP: isPGP};
	$('#'+commitEmailId).html(templateCommitEMailCollapsed(context));

}

function commitEMail(passwordFieldId, keyEntryId, commitEmailId, commitKeyId, collapse2Id, panelId, infoId, actionId, emailAddress, originalFingerprint, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {

	certContainer = listEmailCertificates[emailAddress];
	if (certContainer == null || !certContainer) {
		Application.console.log("certContainer is null");
	}
	/* Debug Only */
	Application.console.log("commitEmailId - PGPKeyStatus: "+certContainer[0].pgpKeyStatus);
	Application.console.log("commitEmailId - SMIMECertStatus: "+certContainer[0].smimeCertStatus);
	/* End - Debug Only */

	if (isPGP == 1) {
		/*
		 * get selected PGP key
		 */
		var pgpKey
		for (var i=0; i<numberPGPKeys; i++) {
			if (($('#'+selectOptionsId+i).attr('checked') == 'checked') || ($('#'+selectOptionsId+i).prop('checked') == true)) {
				var value = $('#'+selectOptionsId+i).attr('value');
				pgpKey = certContainer[0].pgpKeys[value];
			}
		}

		//var pgpKey = certContainer[0].pgpKeys[0];
		var asciiArmoredKey = pgpKey.armor();
		var password = $('#'+passwordFieldId).val();

		var uploadCompleted = $.Deferred();
		processKeyUpload(emailAddress, password, asciiArmoredKey, uploadCompleted);
		$.when(uploadCompleted).done(function(){
			Application.console.log("Key upload finished!");
			if (loginResponse != null && loginResponse.error != null) {
				var messageTitle = "Fehler";
				var messageText = "Beim Veröffentlichen deines Schlüssels ist ein Fehler aufgetreten: "+loginResponse.error;
				var context = {title: messageTitle, message: messageText};
				var html = templateErrorMessage(context);
				$('#messageSection').html(html);

			} else if (uploadResponse != null && uploadResponse.error != null) {
				Application.console.log("Upload response: "+JSON.stringify(uploadResponse));
				var messageTitle = "Fehler";
				var messageText = "Beim Veröffentlichen deines Schlüssels ist ein Fehler aufgetreten: "+uploadResponse.error;
				var context = {title: messageTitle, message: messageText};
				var html = templateErrorMessage(context);
				$('#messageSection').html(html);
			} else {
				// success!
				Application.console.log("Success!");
				$('#'+commitEmailId).addClass('list-group-item-keys4all');
				$('#'+commitEmailId).html(templateCommitEMailMin({}));

				$('#'+commitKeyId).removeClass('disabled');
				var context = {keyEntryId: keyEntryId, collapse2Id: collapse2Id, panelId: panelId, infoId: infoId, actionId: actionId, emailAddress: emailAddress, originalFingerprint: originalFingerprint, numberPGPKeys: numberPGPKeys, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId, isPGP: isPGP};
				$('#'+commitKeyId).html(templateCommitKeyCollapsed(context));
				$('#messageSection').html("");
			}



	    });

	} else {
		/* key upload fuer S/MIME */
		Application.console.log("SMIME KeyUpload");


		//get certificate as der
		var derArray = CertDBManager.getCert(emailAddress);

		// success:
		//$('#'+commitEmailId).addClass('list-group-item-keys4all');
		//$('#'+commitEmailId).html(templateCommitEMailMin({}));


		//TODO: check if cert is found

		// save to file
		AddonManager.getAddonByID("vvv-addon@sit.fraunhofer.de", function(addon) {
			Application.console.log("Addon: "+addon);
			var uri = addon.getResourceURI(".");
			var certPath = uri.path;

			if(CommonUtils.getOS() === "WINNT") {
				if(certPath[0] === '/') {
					certPath = extensionPath.substring(1);
					certPath = extensionPath.replace(/\//g, "\\");
				}
			}
			certPath = certPath +emailAddress + ".der";
			Application.console.log("certPath: " + certPath);


			let promise = OS.File.writeAtomic(certPath, derArray, {});
			promise = promise.then(function onSuccess(data) {
				//deferred.resolve();
				var mailDomain = emailAddress.split("@")[1];
				Application.console.log("Domain: " + mailDomain);
				var ldapAddress = LDAPTool.getVVVLDAP(mailDomain);
				Application.console.log("pw-field-id: " + passwordFieldId);
				var user = emailAddress;
				var pw = $('#'+passwordFieldId).val();
				//check password local
				var isPasswordValid = CommonUtils.checkPassword(emailAddress, pw);
				Application.console.log("isPasswordValid: " + isPasswordValid);

				if( isPasswordValid === false) {
					Application.console.log("Password is not valid");
					var messageTitle = "Es ist ein Fehler aufgetreten!";
					var messageText = "Das eingegebene Passwort ist falsch.";
					var context = {title: messageTitle, message: messageText};
					var html = templateErrorMessage(context);
					$('#messageSection').html(html);
					return;
				}
				LDAPTool.updateCert(ldapAddress, emailAddress, user, pw, certPath, function(response) {
					Application.console.log("update_cert_output: " + response);
					// success:
					$('#'+commitEmailId).addClass('list-group-item-keys4all');
					$('#'+commitEmailId).html(templateCommitEMailMin({}));

					$('#'+commitKeyId).removeClass('disabled');
					var context = {keyEntryId: keyEntryId, collapse2Id: collapse2Id, panelId: panelId, infoId: infoId, actionId: actionId, emailAddress: emailAddress, originalFingerprint: originalFingerprint, numberPGPKeys: 0, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId, isPGP: isPGP};
					$('#'+commitKeyId).html(templateCommitKeyCollapsed(context));
				});
			})
			.catch(function(error) {
				Application.console.log("file creation failed: " + error);
			});
		});
	}
}



function commitKey(keyEntryId, collapse2Id, panelId, infoId, actionId, emailAddress, originalFingerprint, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {
	Application.console.log("commitKey - email address: "+emailAddress);
	Application.console.log("commitKey - isPGP: "+isPGP);

	certContainer = listEmailCertificates[emailAddress];
	if (certContainer == null || !certContainer) {
		Application.console.log("certContainer is null");
	}
	if (isPGP == 1) {
		certContainer[0].pgpKeyStatus = 2;
	} else {
		certContainer[0].smimeCertStatus = 2;
	}

	$('#'+collapse2Id).collapse('hide');
	$('#'+panelId).removeClass('panel-default');
	$('#'+panelId).addClass('panel-published');

	$('#'+infoId).removeAttr('disabled');

	var iconSpanElm = $('#'+actionId).children().first();
	if (iconSpanElm.hasClass('glyphicon-plus')) {
		iconSpanElm.removeClass('glyphicon-plus');
		iconSpanElm.addClass('glyphicon-minus');
	}

	// move key element to the published keys
	var tmp = $('#'+keyEntryId).detach();
	$('#published-keys').append(tmp);

	if (isPGP == 1) {
		addPublishedKeyToFile(emailAddress, "pgp", originalFingerprint);
		numberPublishedKeys++;
		numberUnpublishedKeys--;

		for (var i=0; i<numberPGPKeys; i++) {
			if (($('#'+selectOptionsId+i).attr('checked') == 'checked') || ($('#'+selectOptionsId+i).prop('checked') == true)) {
				Application.console.log(i+": show");
				$('#'+showHideId+i).show();
			} else {
				// hide
				Application.console.log(i+": hide");
				$('#'+showHideId+i).hide();
			}

			$('#'+radioDivId+i).hide();
		}

		// hide badge
		$('#'+badgeId).css("visibility", "hidden");


	} else {
		addPublishedKeyToFile(emailAddress, "smime", originalFingerprint);
		numberPublishedCertificates++;
		numberUnpublishedCertificates--;
	}

	var messageTitle = "Herzlichen Glückwunsch!";
	var messageText = "Du hast erfolgreich deinen Schlüssel veröffentlicht.";
	var context = {title: messageTitle, message: messageText};
	var html = templateSuccessMessage(context);
	$('#messageSection').html(html);

	showCountText();
}

function abortPublication(infoId, keyEntryId, actionId, privacyId, commitEmailId, commitKeyId, collapse2Id, emailAddress, isPGP) {

	Application.console.log("[abortPublication] keyEntryId="+keyEntryId+", actionId="+actionId+", privacyId="+privacyId+", commitEmailId="+commitEmailId+", commitKeyId="+commitKeyId+", collapse2Id="+collapse2Id+", emailAddress="+emailAddress);

	certContainer = listEmailCertificates[emailAddress];
	if (certContainer == null || !certContainer) {
		Application.console.log("certContainer is null");
	}
	if (isPGP == 1) {
		certContainer[0].pgpKeyStatus = 0;
	} else {
		certContainer[0].smimeCertStatus = 0;
	}
	Application.console.log("status: unpublished");

	$('#'+collapse2Id).collapse('hide');
	$('#'+commitEmailId).addClass('disabled');
	$('#'+commitKeyId).addClass('disabled');

	$('#'+actionId).attr('data-toggle', 'collapse');
	$('#'+actionId).attr('data-target', '#'+collapse2Id);

	$('#'+actionId).prop("checked", false);

	if ($('#'+infoId).attr('disabled') == 'disabled') {
		$('#'+infoId).removeAttr('disabled');
	} else {
		$('#'+infoId).attr('disabled', 'disabled');
	}

}

function continuePublication(actionId) {
	$('#'+actionId).prop("checked", true);
}

function abortRevocation(infoId, actionId, collapse2Id, collapse3Id) {
	Application.console.log("abort Revocation. infoId: "+infoId+", actionId: "+actionId+", collapse2Id: "+collapse2Id+", collapse3Id: "+collapse3Id);

	$('#'+actionId).prop("checked", true);

	//if ($('#'+actionId).attr('data-target') == '#'+collapse3Id) {
		$('#'+infoId).removeAttr('disabled');

		$('#'+actionId).attr('data-toggle', 'collapse');
		$('#'+actionId).attr('data-target', '#'+collapse2Id);
		$('#'+collapse3Id).collapse('hide');
		$('#'+collapse2Id).collapse('hide');
	//}
}

function continueRevocation(passwordFieldId, revocationId, infoId, keyEntryId, actionId, panelId, privacyId, commitEmailId, commitKeyId, collapse1Id, collapse2Id, collapse3Id, emailAddress, originalFingerprint, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {

	Application.console.log("continue Revocation. revocationId: "+revocationId);

	if ($('#'+actionId).attr('data-target') != '#'+collapse3Id) {

		if ($('#'+infoId).attr('disabled') == 'disabled') {
			$('#'+infoId).removeAttr('disabled');
		} else {
			$('#'+infoId).attr('disabled', 'disabled');
		}

		var iconSpanElm = $('#'+infoId).children().first();
		if (iconSpanElm.hasClass('glyphicon-triangle-top')) {
			iconSpanElm.removeClass('glyphicon-triangle-top');
			iconSpanElm.addClass('glyphicon-triangle-bottom');
		}

		var context = {emailAddress: emailAddress, passwordFieldId: passwordFieldId, keyEntryId: keyEntryId, commitEmailId: commitEmailId, commitKeyId: commitKeyId, collapse2Id: collapse2Id, collapse3Id: collapse3Id, panelId: panelId, infoId: infoId, actionId: actionId, originalFingerprint: originalFingerprint, numberPGPKeys: numberPGPKeys, selectOptionsId: selectOptionsId, showHideId: showHideId, badgeId: badgeId, radioDivId: radioDivId, isPGP: isPGP};
		var html = templateRevokePublicationCollapsed(context);
		$('#'+revocationId).html(html);

		$('#'+actionId).attr('data-toggle', 'collapse');
		$('#'+actionId).attr('data-target', '#'+collapse3Id);
		$('#'+collapse3Id).collapse('show');
		$('#'+collapse1Id).collapse('hide');

		$('#'+actionId).prop("checked", false);
	}
}

function commitEMailRevocation(passwordFieldId, keyEntryId, commitEmailId, commitKeyId, collapse2Id, collapse3Id, panelId, infoId, actionId, emailAddress, originalFingerprint, numberPGPKeys, selectOptionsId, showHideId, badgeId, radioDivId, isPGP) {

	Application.console.log("[commitEMailRevocation] email: "+emailAddress);

	certContainer = listEmailCertificates[emailAddress];
	if (certContainer == null || !certContainer) {
		Application.console.log("certContainer is null");
	}

	if (isPGP == 1) {
		var password = $('#'+passwordFieldId).val();

		var revokeCompleted = $.Deferred();
		processKeyDelete(emailAddress, password, revokeCompleted);
		$.when(revokeCompleted).done(function(){
			Application.console.log("Key revocation finished!");
			if (loginResponse != null && loginResponse.error != null) {
				var messageTitle = "Fehler";
				var messageText = "Beim Widerrufen der Veröffentlichung deines Schlüssels ist ein Fehler aufgetreten: "+loginResponse.error;
				var html = Mustache.render(templateErrorMessage, {title: messageTitle, message: messageText});
				$('#messageSection').html(html);

			} else {
				// success!
				Application.console.log("Revocation Success!");

				certContainer[0].pgpKeyStatus = 0;

				$('#'+panelId).addClass('panel-default');
				$('#'+panelId).removeClass('panel-published');

				$('#'+actionId).attr('data-toggle', 'collapse');
				$('#'+actionId).attr('data-target', '#'+collapse2Id);
				$('#'+collapse3Id).collapse('hide');

				$('#'+infoId).removeAttr('disabled');

				var iconSpanElm = $('#'+actionId).children().first();
				if (iconSpanElm.hasClass('glyphicon-minus')) {
					iconSpanElm.removeClass('glyphicon-minus');
					iconSpanElm.addClass('glyphicon-plus');
				}

				// move key element to the unpublished keys
				var tmp = $('#'+keyEntryId).detach();
				$('#unpublished-keys').append(tmp);

				if (isPGP == 1) {
					/*
					 * get selected PGP key
					 */
					var pgpKey
					for (var i=0; i<numberPGPKeys; i++) {
						if (($('#'+selectOptionsId+i).attr('checked') == 'checked') || ($('#'+selectOptionsId+i).prop('checked') == true)) {
							var value = $('#'+selectOptionsId+i).attr('value');
							pgpKey = certContainer[0].pgpKeys[value];
						}
					}

					originalFingerprint = pgpKey.primaryKey.getFingerprint();


					removePublishedKeyFromFile(emailAddress, "pgp", originalFingerprint);
					numberPublishedKeys--;
					numberUnpublishedKeys++;

					for (var i=0; i<numberPGPKeys; i++) {
						$('#'+showHideId+i).show();
						$('#'+radioDivId+i).show();
					}

					// show badge
					$('#'+badgeId).css("visibility", "visible");

				} else {
					removePublishedKeyFromFile(emailAddress, "smime", originalFingerprint);
					numberPublishedCertificates--;
					numberUnpublishedCertificates++;
				}

				var messageTitle = "Veröffentlichung widerrufen!";
				var messageText = "Du hast erfolgreich die Veröffentlichung deines Schlüssels widerrufen.";
				var context = {title: messageTitle, message: messageText};
				var html = templateSuccessMessage(context);
				$('#messageSection').html(html);

				showCountText();
			}



	    });

	} else {
		/* key upload fuer S/MIME */


		/* key upload fuer S/MIME */
		Application.console.log("SMIME KeyUpload");


		//get certificate as der
		var derArray = CertDBManager.getCert(emailAddress);

		// success:
		$('#'+commitEmailId).addClass('list-group-item-keys4all');
		$('#'+commitEmailId).html(templateCommitEMailMin({}));


		//TODO: check if cert is found
		var mailDomain = emailAddress.split("@")[1];
		Application.console.log("Domain: " + mailDomain);
		//TODO: DNSSEC-check/delete hardcoded ldap address
		var ldapAddress = LDAPTool.getVVVLDAP(mailDomain);
		Application.console.log("pw-field-id: " + passwordFieldId);
		var pw = $('#'+passwordFieldId).val();
		//check password local
		var isPasswordValid = CommonUtils.checkPassword(emailAddress, pw);
		Application.console.log("isPasswordValid: " + isPasswordValid);

		if( isPasswordValid === false) {
			//TODO: flash message
			Application.console.log("Password is not valid");
			var messageTitle = "Es ist ein Fehler aufgetreten!";
			var messageText = "Das eingegebene Passwort ist falsch.";
			var context = {title: messageTitle, message: messageText};
			var html = templateErrorMessage(context);
			$('#messageSection').html(html);
			return;
		}

		var user = emailAddress.split("@")[0];
		LDAPTool.deleteCert(ldapAddress, emailAddress, user, pw, function(response) {
			Application.console.log("delete_cert_output: " + response);
			// success:
			certContainer[0].smimeCertStatus = 0;

			$('#'+panelId).addClass('panel-default');
			$('#'+panelId).removeClass('panel-published');

			$('#'+actionId).attr('data-toggle', 'collapse');
			$('#'+actionId).attr('data-target', '#'+collapse2Id);
			$('#'+collapse3Id).collapse('hide');

			$('#'+infoId).removeAttr('disabled');

			var iconSpanElm = $('#'+actionId).children().first();
			if (iconSpanElm.hasClass('glyphicon-minus')) {
				iconSpanElm.removeClass('glyphicon-minus');
				iconSpanElm.addClass('glyphicon-plus');
			}

			// move key element to the published keys
			var tmp = $('#'+keyEntryId).detach();
			$('#unpublished-keys').append(tmp);

			if (isPGP == 1) {
				removePublishedKeyFromFile(emailAddress, "pgp", originalFingerprint);
				numberPublishedKeys--;
				numberUnpublishedKeys++;
			} else {
				removePublishedKeyFromFile(emailAddress, "smime", originalFingerprint);
				numberPublishedCertificates--;
				numberUnpublishedCertificates++;
			}

			var messageTitle = "Veröffentlichung widerrufen!";
			var messageText = "Du hast erfolgreich die Veröffentlichung deines Schlüssels widerrufen.";
			var context = {title: messageTitle, message: messageText};
			var html = templateSuccessMessage(context);
			$('#messageSection').html(html);

			showCountText();
		});


	}
}

function insertLineBreaks(s) {
	var maxLineLength = 50;
	var index = 0;
	var stringWithLineBreaks = "";
	while (s.length > maxLineLength) {
		var firstPart = s.substring(index, maxLineLength);
		s = s.substring(maxLineLength);
		stringWithLineBreaks = stringWithLineBreaks + firstPart + " ";
	}
	stringWithLineBreaks = stringWithLineBreaks + s;

	return stringWithLineBreaks;
}

function cutString(s) {
	var maxLineLength = 50;
	return s.substring(0, maxLineLength)+"[...]";
}

function showHelpText(index) {
	var html = "";
	if (index === 1) {
		html = templateHelpTextPublicKey({});
		$('#helpTextNav1').addClass( 'active' ).siblings().removeClass( 'active' );
	} else if (index === 2) {
		html = templateHelpTextCertificate({});
		$('#helpTextNav2').addClass( 'active' ).siblings().removeClass( 'active' );
	} else if (index === 3) {
		html = templateHelpTextEncryptedMail({});
		$('#helpTextNav3').addClass( 'active' ).siblings().removeClass( 'active' );
	}
	$("#helpTextContent").html(html);
}

function toggleInfoButton(infoId, collapse1IdBody, emailAddress, isPGP) {
	var iconSpanElm = $('#'+infoId).children().first();
	if (iconSpanElm.hasClass('glyphicon-triangle-bottom')) {
		iconSpanElm.removeClass('glyphicon-triangle-bottom');
		iconSpanElm.addClass('glyphicon-triangle-top');

		var certContainer = listEmailCertificates[emailAddress];
		if (certContainer == null || !certContainer) {
			Application.console.log("certContainer is null");
		} else {
			if ((isPGP == 1 && certContainer[0].pgpKeyStatus == 2) || (isPGP == 0 && certContainer[0].smimeCertStatus == 2)) {
				var html = templatePrivacyAgreementRevovation({});
				$("#"+collapse1IdBody).html(html);
			} else {
				$("#"+collapse1IdBody).html("");
			}
		}

	} else {
		iconSpanElm.removeClass('glyphicon-triangle-top');
		iconSpanElm.addClass('glyphicon-triangle-bottom');
	}



}

function initInfoModal(clickedLinkId, linkId2, linkId3, clickedCollapseId, collapseId2, collapseId3) {
	var iconElm = $('#'+clickedLinkId).children().first();
	iconElm.attr('src', 'img/button-retract.png');

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
}


function toggleModalButton(clickedLinkId, linkId2, linkId3, clickedCollapseId, collapseId2, collapseId3) {
	var iconElm = $('#'+clickedLinkId).children().first();
	if (iconElm.attr('src') == 'img/button-extend.png') {
		iconElm.attr('src', 'img/button-retract.png');
	} else {
		iconElm.attr('src', 'img/button-extend.png');
	}

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
}

function initInfoModalPGP(clickedLinkId, linkId2, linkId3, clickedCollapseId, collapseId2, collapseId3) {
	var iconElm = $('#'+clickedLinkId).children().first();
	iconElm.attr('src', 'img/button-retract.png');

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
}


function toggleModalButtonPGP(clickedLinkId, linkId2, linkId3, clickedCollapseId, collapseId2, collapseId3) {
	var iconElm = $('#'+clickedLinkId).children().first();
	if (iconElm.attr('src') == 'img/button-extend.png') {
		iconElm.attr('src', 'img/button-retract.png');
	} else {
		iconElm.attr('src', 'img/button-extend.png');
	}

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
}

function initInfoModalSMIME(clickedLinkId, linkId2, linkId3, linkId4, linkId5, clickedCollapseId, collapseId2, collapseId3, collapseId4, collapseId5) {
	var iconElm = $('#'+clickedLinkId).children().first();
	iconElm.attr('src', 'img/button-retract.png');

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	var iconElm4 = $('#'+linkId4).children().first();
	iconElm4.attr('src', 'img/button-extend.png');

	var iconElm5 = $('#'+linkId5).children().first();
	iconElm5.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
	$('#'+collapseId4).collapse('hide');
	$('#'+collapseId5).collapse('hide');
}


function toggleModalButtonSMIME(clickedLinkId, linkId2, linkId3, linkId4, linkId5, clickedCollapseId, collapseId2, collapseId3, collapseId4, collapseId5) {
	var iconElm = $('#'+clickedLinkId).children().first();
	if (iconElm.attr('src') == 'img/button-extend.png') {
		iconElm.attr('src', 'img/button-retract.png');
	} else {
		iconElm.attr('src', 'img/button-extend.png');
	}

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	var iconElm4 = $('#'+linkId4).children().first();
	iconElm4.attr('src', 'img/button-extend.png');

	var iconElm5 = $('#'+linkId5).children().first();
	iconElm5.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
	$('#'+collapseId4).collapse('hide');
	$('#'+collapseId5).collapse('hide');
}

function initInfoModalPrivacy(clickedLinkId, linkId2, linkId3, linkId4, linkId5, linkId6, linkId7, linkId8, linkId9, linkId10, linkId11, clickedCollapseId, collapseId2, collapseId3, collapseId4, collapseId5, collapseId6, collapseId7, collapseId8, collapseId9, collapseId10, collapseId11) {
	var iconElm = $('#'+clickedLinkId).children().first();
	iconElm.attr('src', 'img/button-retract.png');

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	var iconElm4 = $('#'+linkId4).children().first();
	iconElm4.attr('src', 'img/button-extend.png');

	var iconElm5 = $('#'+linkId5).children().first();
	iconElm5.attr('src', 'img/button-extend.png');

	var iconElm6 = $('#'+linkId6).children().first();
	iconElm6.attr('src', 'img/button-extend.png');

	var iconElm7 = $('#'+linkId7).children().first();
	iconElm7.attr('src', 'img/button-extend.png');

	var iconElm8 = $('#'+linkId8).children().first();
	iconElm8.attr('src', 'img/button-extend.png');

	var iconElm9 = $('#'+linkId9).children().first();
	iconElm9.attr('src', 'img/button-extend.png');

	var iconElm10 = $('#'+linkId10).children().first();
	iconElm10.attr('src', 'img/button-extend.png');

	var iconElm11 = $('#'+linkId11).children().first();
	iconElm11.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
	$('#'+collapseId4).collapse('hide');
	$('#'+collapseId5).collapse('hide');
	$('#'+collapseId6).collapse('hide');
	$('#'+collapseId7).collapse('hide');
	$('#'+collapseId8).collapse('hide');
	$('#'+collapseId9).collapse('hide');
	$('#'+collapseId10).collapse('hide');
	$('#'+collapseId11).collapse('hide');
}


function toggleModalButtonPrivacy(clickedLinkId, linkId2, linkId3, linkId4, linkId5, linkId6, linkId7, linkId8, linkId9, linkId10, linkId11, clickedCollapseId, collapseId2, collapseId3, collapseId4, collapseId5, collapseId6, collapseId7, collapseId8, collapseId9, collapseId10, collapseId11) {
	var iconElm = $('#'+clickedLinkId).children().first();
	if (iconElm.attr('src') == 'img/button-extend.png') {
		iconElm.attr('src', 'img/button-retract.png');
	} else {
		iconElm.attr('src', 'img/button-extend.png');
	}

	var iconElm2 = $('#'+linkId2).children().first();
	iconElm2.attr('src', 'img/button-extend.png');

	var iconElm3 = $('#'+linkId3).children().first();
	iconElm3.attr('src', 'img/button-extend.png');

	var iconElm4 = $('#'+linkId4).children().first();
	iconElm4.attr('src', 'img/button-extend.png');

	var iconElm5 = $('#'+linkId5).children().first();
	iconElm5.attr('src', 'img/button-extend.png');

	var iconElm6 = $('#'+linkId6).children().first();
	iconElm6.attr('src', 'img/button-extend.png');

	var iconElm7 = $('#'+linkId7).children().first();
	iconElm7.attr('src', 'img/button-extend.png');

	var iconElm8 = $('#'+linkId8).children().first();
	iconElm8.attr('src', 'img/button-extend.png');

	var iconElm9 = $('#'+linkId9).children().first();
	iconElm9.attr('src', 'img/button-extend.png');

	var iconElm10 = $('#'+linkId10).children().first();
	iconElm10.attr('src', 'img/button-extend.png');

	var iconElm11 = $('#'+linkId11).children().first();
	iconElm11.attr('src', 'img/button-extend.png');

	$('#'+clickedCollapseId).collapse('show');
	$('#'+collapseId2).collapse('hide');
	$('#'+collapseId3).collapse('hide');
	$('#'+collapseId4).collapse('hide');
	$('#'+collapseId5).collapse('hide');
	$('#'+collapseId6).collapse('hide');
	$('#'+collapseId7).collapse('hide');
	$('#'+collapseId8).collapse('hide');
	$('#'+collapseId9).collapse('hide');
	$('#'+collapseId10).collapse('hide');
	$('#'+collapseId11).collapse('hide');
}

function showCountText() {
	var countText = "";
	var keyText = "";
	var certText = "";

	var numberOfKeys = numberPublishedKeys + numberUnpublishedKeys;
	var numberOfCerts = numberPublishedCertificates + numberUnpublishedCertificates;

	keyText = numberPublishedKeys + " / " + numberOfKeys;
	certText = numberPublishedCertificates + " / " + numberOfCerts;
	$("#key-counter").html(keyText);
	$("#certificate-counter").html(certText);

}

function changeRadioButtonText(selectOptionsId, index, numberPGPKeys) {
	for (var i=0; i<numberPGPKeys; i++) {
		$('label[for='+selectOptionsId+i+']').html("<span class='font-black'>Diesen Schlüssel auswählen</span>");
	}
	$('label[for='+selectOptionsId+index+']').html("<span class='font-black-bold'>Dieser Schlüssel ist ausgewählt</span>");
}
