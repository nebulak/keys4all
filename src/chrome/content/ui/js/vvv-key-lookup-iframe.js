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
const nsIX509CertDB = Components.interfaces.nsIX509CertDB;
const nsX509CertDBContractID = "@mozilla.org/security/x509certdb;1";
const nsIX509Cert = Components.interfaces.nsIX509Cert;


var recipientsModel = {};
var senderKeyInfo = null;
var currentRecipients = [];

var gMsgCompose = null;
var composerDocument = null;




document.addEventListener("vvv", parentEventHandler, false);



KeyDiscoverer.callback = function (recipientsToProcess, processedRecipients) {
  //TODO: delete
  //Application.console.log("Wait Queue: " + JSON.stringify(recipientsToProcess) + "\nProcessed Queue: " + JSON.stringify(processedRecipients));
  //TODO: filter with currentRecipients
  recipientsModel.sender = senderKeyInfo;
  recipientsModel.recipientsToProcess = KeyDiscoverer.recipientsToProcess;

  Application.console.log("RecipientsModel: " + JSON.stringify(recipientsModel));
  var currentProcessedRecipients = [];

  //filter processed recipients
  for (var i=0; i<currentRecipients.length; i++) {
    for(var j=0; j<processedRecipients.length; j++) {
      if(processedRecipients[j].email == currentRecipients[i]) {
        currentProcessedRecipients.push(processedRecipients[j]);
        break;
      }
    }
  }
  recipientsModel.processedRecipients = currentProcessedRecipients;
  Application.console.log("Callback RecipientsModel: " + JSON.stringify(recipientsModel));

  if(currentRecipients.length === 0)
  {
    Application.console.log("Render Empty Key Table");
    var tempRec = {};
    tempRec.sender = senderKeyInfo;
    tempRec.recipientsToProcess = [];
    tempRec.processedRecipients = [];
    var source   = $("#iframe-key-table").html();
    var template = Handlebars.compile(source);
    var html     = template(recipientsModel);
    document.getElementById("vvv-iframe-body").innerHTML = html;
  }
  else
  {
    var source   = $("#iframe-key-table").html();
    var template = Handlebars.compile(source);
    var html     = template(recipientsModel);
    document.getElementById("vvv-iframe-body").innerHTML = html;

  }


  setTimeout(function () {
    var eventForParent = new CustomEvent('vvv-mail', {});
    var parentWindow = window.parent;//top;
    parentWindow.addressOnChangeVVV();
    //parentWindow.document.dispatchEvent(eventForParent);
    Application.console.log("Test");
  }, 500);


  setTimeout(showRecommendations(), 500);




};


function parentEventHandler(e) {
  //parse event data
  gMsgCompose = e.detail.gMsgCompose;
  composerDocument = e.detail.composerDocument;
  if(e.detail.action == "render") {
    var data = e.detail.data;
    if(e.detail.template === "iframe-key-table") {
      currentRecipients = data.recipients;
      //get key info for sender
      if(senderKeyInfo === null) {
        senderKeyInfo = {};
        KeyManager.init();
        Application.console.log(JSON.stringify(data));
        senderKeyInfo.address = data.sender.address;
        if(KeyManager.isPubKeyAvailable(data.sender.address)) {
          senderKeyInfo.pgp = true;
        } else {
          senderKeyInfo.pgp = false;
        }

        if(KeyManager.isCertAvailable(data.sender.address)) {
          senderKeyInfo.smime = true;
        } else {
          senderKeyInfo.smime = false;
        }
      }

      recipientsModel.sender = senderKeyInfo;
      recipientsModel.recipientsToProcess = KeyDiscoverer.recipientsToProcess;

      var currentProcessedRecipients = [];

      //filter processed recipients
      for (var i=0; i<currentRecipients.length; i++) {
        for(var j=0; j<KeyDiscoverer.processedRecipients.length; j++) {
          if(KeyDiscoverer.processedRecipients[j].email == currentRecipients[i].address) {
            currentProcessedRecipients.push(KeyDiscoverer.processedRecipients[j]);
            break;
          }
        }
      }
      Application.console.log("prec " + JSON.stringify(KeyDiscoverer.processedRecipients));
      recipientsModel.processedRecipients = currentProcessedRecipients;

      recipientsModel.pgpRecipientsInQueue = KeyDiscoverer.pgpRecipientsInQueue;
      Application.console.log("RecipientsModel: " + JSON.stringify(recipientsModel));

      if(data.recipients.length === 0)
      {
        Application.console.log("Render Empty Key Table");
        var tempRec = {};
        tempRec.sender = senderKeyInfo;
        tempRec.recipientsToProcess = [];
        tempRec.processedRecipients = [];
        var source   = $("#iframe-key-table").html();
        var template = Handlebars.compile(source);
        var html     = template(recipientsModel);
        document.getElementById("vvv-iframe-body").innerHTML = html;

      }
      else
      {
        var source   = $("#iframe-key-table").html();
        var template = Handlebars.compile(source);
        var html     = template(recipientsModel);
        document.getElementById("vvv-iframe-body").innerHTML = html;
        Application.console.log("recipientsModel for Table: " + JSON.stringify(recipientsModel));
        Application.console.log("current recipients: " + JSON.stringify(currentRecipients));
        var recommendationSource = $("#recommendation-blank").html();
        template = Handlebars.compile(recommendationSource);
        html = template();
        document.getElementById("recommendation-content").innerHTML = html;

        composerDocument.getElementById("button-send").setAttribute("disabled", "true");

        var recipientsList = [];
        for(var i=0; i<data.recipients.length; i++) {
          recipientsList.push(data.recipients[i].address);
          currentRecipients = recipientsList;
        }
        KeyDiscoverer.addRecipients(recipientsList);
      }


      if(recipientsModel.recipientsToProcess.length == 0)
      {
        setTimeout(showRecommendations(), 500);

      }
      else
      {
        document.getElementById("recommendation-content").innerHTML = "";
      }
    }
    else
    {
    	var source   = $("#iframe-encryption-disabled").html();
    	var template = Handlebars.compile(source);
    	var html     = template({});
    	document.getElementById("vvv-iframe-body").innerHTML = html;

    	composerDocument.getElementById("button-send").setAttribute("disabled", "");
      setTimeout(showRecommendations(), 500);

    }
  }

}




function showRecommendations() {
	/*
	 * Show recommendations
	 */

 if(typeof recipientsModel.processedRecipients === "undefined" ||
    typeof recipientsModel.recipientsInProgress === "undefined"
 )
 {
   Application.console.log("recipientsModel:undefined");
   recipientsModel.processedRecipients = [];
   recipientsModel.recipientsInProgress = [];
 }

 if(recipientsModel.processedRecipients.length === 0 && recipientsModel.recipientsInProgress.length === 0)
  {
    Application.console.log("Greybox Recommendation");
    try {
      document.getElementById("recommendation-content").innerHTML = "";
    } catch (e) {

    } finally {

    }

    return;
  }

	if (recipientsModel.sender.pgp == false && recipientsModel.sender.smime == false) {
		/*
		 * Sender has no key.
		 * Recommendations: sender should get a PGP key and/or S/MIME certificate.
		 * Send e-mail without encryption
		 */
		var recommendationSource = $("#recommendation-key-required").html();
		var template = Handlebars.compile(recommendationSource);
		var context = {text: "Du benötigst einen PGP-Schlüssel oder ein S/MIME-Zertifikat, um verschlüsselte E-Mails senden zu können."};
		var html = template(context);
		document.getElementById("recommendation-content").innerHTML = html;

		$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

		composerDocument.getElementById("button-send").setAttribute("disabled", "true");

	} else if (recipientsModel.sender.pgp == true && recipientsModel.sender.smime == false) {
		/*
		 * Sender has only PGP key:
		 */
		if (haveAllRecipientsPGP() == true) {
			/*
			 * all recipients have a PGP key: encryption possible!
			 */
			var recommendationSource = $("#recommendation-success").html();
			var template = Handlebars.compile(recommendationSource);
			var html = template();
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill").addClass("content-fill-success");

			composerDocument.getElementById("button-send").setAttribute("disabled", "");

		} else if (haveAllRecipientsNoKey() == true) {
			/*
			 * all recipients have neither a PGP key nor an S/MIME certificate:
			 * Send e-mail without encryption, insert recommendation
			 */
			var recommendationSource = $("#recommendation-add-text").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Deine Empfänger benötigen einen PGP-Schlüssel, damit diese E-Mail verschlüsselt werden kann.", keytype: 1};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveAllRecipientsOnlySMIME() == true) {
			/*
			 * all recipients have only S/MIME certificate (and no PGP key):
			 * Encryption not possible, sender should get an S/MIME certificate.
			 */
			var recommendationSource = $("#recommendation-key-required").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Du hast nur einen PGP-Schlüssel, aber die Empfänger haben ausschließlich S/MIME-Zertifikate. Besorge dir doch ebenfalls ein S/MIME-Zertifikat, um diesen Empfängern verschlüsselte E-Mails senden zu können."};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsOnlySMIME() == false) {
			/*
			 * Some recipients have a PGP key and some recipients have no key:
			 * Duplicate e-mail and send two separate e-mails.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen einen PGP-Schlüssel, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst.",
			numberOfMails: 2, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "nopgpGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsOnlySMIME() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsPGP() == false) {
			/*
			 * Some recipients have only an S/MIME certificate and some recipients have no key:
			 * Encryption not possible, sender should get an S/MIME certificate.
			 */
			var recommendationSource = $("#recommendation-key-required").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Du hast nur einen PGP-Schlüssel, aber die Empfänger haben entweder nur ein S/MIME-Zertifikat oder gar keinen Schlüssel. Tipp: Besorge dir doch ebenfalls ein S/MIME-Zertifikat."};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsOnlySMIME() == true && haveSomeRecipientsNoKey() == false) {
			/*
			 * Some recipients have a PGP key and some recipients have only an S/MIME certificate:
			 * Duplicate e-mail and send two separate e-mails. Recommendation: sender should get an S/MIME certificate.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen einen PGP-Schlüssel, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst. Tipp: Besorge dir doch ebenfalls ein S/MIME-Zertifikat.",
			numberOfMails: 2, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "nopgpGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsOnlySMIME() == true && haveSomeRecipientsNoKey() == true) {
			/*
			 * Some recipients have a PGP key and some recipients have only an S/MIME certificate and some recipients have no key:
			 * Duplicate e-mail and send two separate e-mails. Recommendation: sender should get an S/MIME certificate.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen einen PGP-Schlüssel, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst. Tipp: Besorge dir doch ebenfalls ein S/MIME-Zertifikat.",
			numberOfMails: 2, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "nopgpGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		}
	} else if (recipientsModel.sender.pgp == false && recipientsModel.sender.smime == true) {
		/*
		 * Sender has only S/MIME certificate:
		 */
		if (haveAllRecipientsSMIME() == true) {
			/*
			 * all recipients have an S/MIME certificate: encryption possible!
			 */
			var recommendationSource = $("#recommendation-success").html();
			var template = Handlebars.compile(recommendationSource);
			var html = template();
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill").addClass("content-fill-success");

			composerDocument.getElementById("button-send").setAttribute("disabled", "");

		} else if (haveAllRecipientsNoKey() == true) {
			/*
			 * all recipients have neither a PGP key nor an S/MIME certificate:
			 * Send e-mail without encryption, insert recommendation
			 */
			var recommendationSource = $("#recommendation-add-text").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Deine Empfänger benötigen ein S/MIME-Zertifikat, damit diese E-Mail verschlüsselt werden kann.", keytype: 2};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveAllRecipientsOnlyPGP() == true) {
			/*
			 * all recipients have only PGP key (and no S/MIME certificate):
			 * Encryption not possible, sender should get an S/MIME certificate.
			 */
			var recommendationSource = $("#recommendation-key-required").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Du hast nur ein S/MIME-Zertifikat, aber die Empfänger haben ausschließlich PGP-Schlüssel. Besorge dir doch ebenfalls einen PGP-Schlüssel, um diesen Empfängern verschlüsselte E-Mails senden zu können."};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsSMIME() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsOnlyPGP() == false) {
			/*
			 * Some recipients have an S/MIME certificate and some recipients have no key:
			 * Duplicate e-mail and send two separate e-mails.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen ein S/MIME-Zertifikat, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst.",
			numberOfMails: 2, recipientGroupMail1: "smimeGroup", recipientGroupMail2: "nosmimeGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsOnlyPGP() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsSMIME() == false) {
			/*
			 * Some recipients have only a PGP key and some recipients have no key:
			 * Encryption not possible, sender should get a PGP key.
			 */
			var recommendationSource = $("#recommendation-key-required").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Du hast nur ein S/MIME-Zertifikat, aber die Empfänger haben entweder nur einen PGP-Schlüssel oder gar keinen Schlüssel. Tipp: Besorge dir doch ebenfalls einen PGP-Schlüssel."};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsSMIME() == true && haveSomeRecipientsOnlyPGP() == true && haveSomeRecipientsNoKey() == false) {
			/*
			 * Some recipients have an S/MIME certificate and some recipients have only a PGP key:
			 * Duplicate e-mail and send two separate e-mails. Recommendation: sender should get a PGP key.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen ein S/MIME-Zertifikat, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst. Tipp: Besorge dir doch ebenfalls einen PGP-Schlüssel.",
			numberOfMails: 2, recipientGroupMail1: "smimeGroup", recipientGroupMail2: "nosmimeGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsSMIME() == true && haveSomeRecipientsOnlyPGP() == true && haveSomeRecipientsNoKey() == true) {
			/*
			 * Some recipients have an S/MIME certificate and some recipients have only a PGP key and some recipients have no key:
			 * Duplicate e-mail and send two separate e-mails. Recommendation: sender should get a PGP key.
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen ein S/MIME-Zertifikat, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst. Tipp: Besorge dir doch ebenfalls einen PGP-Schlüssel.",
			numberOfMails: 2, recipientGroupMail1: "smimeGroup", recipientGroupMail2: "nosmimeGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		}

	} else if (recipientsModel.sender.pgp == true && recipientsModel.sender.smime == true) {
		/*
		 * Sender has both PGP key and S/MIME certificate:
		 */
		if (haveAllRecipientsPGP() == true) {
			/*
			 * all recipients have a PGP key: encryption possible!
			 */
			var recommendationSource = $("#recommendation-success").html();
			var template = Handlebars.compile(recommendationSource);
			var html = template();
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill").addClass("content-fill-success");

			composerDocument.getElementById("button-send").setAttribute("disabled", "");

		} else if (haveAllRecipientsSMIME() == true) {
			/*
			 * all recipients have an S/MIME certificate: encryption possible!
			 */
			var recommendationSource = $("#recommendation-success").html();
			var template = Handlebars.compile(recommendationSource);
			var html = template();
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill").addClass("content-fill-success");

			composerDocument.getElementById("button-send").setAttribute("disabled", "");

		} else if (haveAllRecipientsNoKey() == true) {
			/*
			 * all recipients have neither a PGP key nor an S/MIME certificate:
			 * Send e-mail without encryption, insert recommendation
			 */
			var recommendationSource = $("#recommendation-add-text").html();
			var template = Handlebars.compile(recommendationSource);
			var context = {text: "Deine Empfänger benötigen entweder einen PGP-Schlüssel oder ein S/MIME-Zertifikat, damit diese E-Mail verschlüsselt werden kann.", keytype: 3};
			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsOnlySMIME() == false) {
			/*
			 * Some recipients have a PGP key and some have no key:
			 * Duplicate e-mail and send two separate e-mails (one without encryption).
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen einen PGP-Schlüssel oder ein S/MIME-Zertifikat, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst.",
			numberOfMails: 2, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "nopgpGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsSMIME() == true && haveSomeRecipientsNoKey() == true && haveSomeRecipientsOnlyPGP() == false) {
			/*
			 * Some recipients have an S/MIME certificate and some have no key:
			 * Duplicate e-mail and send two separate e-mails (one without encryption).
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Alle Empfänger benötigen einen PGP-Schlüssel oder ein S/MIME-Zertifikat, damit die E-Mail an alle verschlüsselt werden kann.",
			text2: "Du kannst die E-Mail an einen Teil der Empfänger verschlüsselt versenden und an den übrigen Teil unverschlüsselt, indem du zwei separate E-Mails schickst.",
			numberOfMails: 2, recipientGroupMail1: "smimeGroup", recipientGroupMail2: "nosmimeGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsSMIME() == true && haveSomeRecipientsNoKey() == false) {
			/*
			 * Some recipients have a PGP key and some recipients have an S/MIME certificate:
			 * Duplicate e-mail and send two separate e-mails (both encrypted).
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Die E-Mail kann nicht verschlüsselt werden, da ein Teil der Empfänger nur einen PGP-Schlüssel hat und ein Teil nur ein S/MIME-Zertifikat.",
			text2: "Du kannst zwei separate E-Mails schicken, die eine wird mit PGP verschlüsselt und die andere mittels S/MIME.",
			numberOfMails: 2, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "nopgpGroup", recipientGroupMail3: ""};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;

			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		} else if (haveSomeRecipientsPGP() == true && haveSomeRecipientsSMIME() == true && haveSomeRecipientsNoKey() == true) {
			/*
			 * Some recipients have a PGP key, some recipients have an S/MIME certificate and some recipients have no key:
			 * Send three separate e-mails (one with PGP encryption, one with S/MIME encryption and on without encryption)
			 */
			var recommendationSource = $("#recommendation-separate-mails").html();
			var template = Handlebars.compile(recommendationSource);

			var context = {text1: "Die E-Mail kann nicht verschlüsselt werden, da ein Teil der Empfänger nur einen PGP-Schlüssel hat, ein Teil nur ein S/MIME-Zertifikat und ein weiterer Teil der Empfänger gar keinen Schlüssel besitzt.",
			text2: "Du kannst drei separate E-Mails schicken, die erste E-Mail wird mit PGP verschlüsselt, die zweite E-Mail wird mittels S/MIME verschlüsselt und die andere wird unverschlüsselt gesendet.",
			numberOfMails: 3, recipientGroupMail1: "pgpGroup", recipientGroupMail2: "smimeOnlyGroup", recipientGroupMail3: "nokeyGroup"};

			var html = template(context);
			document.getElementById("recommendation-content").innerHTML = html;


			$("#vvv-iframe-recommendations").removeClass("content-fill-success").addClass("content-fill");

			composerDocument.getElementById("button-send").setAttribute("disabled", "true");

		}
	}
}

/*
 * Checks if all recipients have neither a PGP key nor an S/MIME certificate.
 * Returns false if at least one recipient has some key.
 */
function haveAllRecipientsNoKey() {
	let nokey = true;
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == true || processedRecipients[i].isPGPVVV == true ||
				processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true) {
			nokey = false;
		}
	}
	return nokey;
}

/*
 * Checks if all recipients have at least a PGP key (they may also have an S/MIME certificate).
 */
function haveAllRecipientsPGP() {
	let allPGP = true;
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false) {
			allPGP = false;
		}
	}
	return allPGP;
}

/*
 * Checks if all recipients have at least an S/MIME certificate (they may also have a PGP key).
 */
function haveAllRecipientsSMIME() {
	let allSMIME = true;
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false) {
			allSMIME = false;
		}
	}
	return allSMIME;
}

/*
 * Checks if all recipients have only a PGP key (and no S/MIME certificate).
 */
function haveAllRecipientsOnlyPGP() {
	let allPGP = true;
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if ((processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false) || (processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true)) {
			allPGP = false;
		}
	}
	return allPGP;
}

/*
 * Checks if all recipients have only an S/MIME certificate (and no PGP key).
 */
function haveAllRecipientsOnlySMIME() {
	let allSMIME = true;
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if ((processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false) || (processedRecipients[i].isPGPAvailable == true || processedRecipients[i].isPGPVVV == true)) {
			allSMIME = false;
		}
	}
	return allSMIME;
}

/*
 * Checks if some recipients have neither a PGP key nor an S/MIME certificate.
 * Returns true if at least one recipient has no key.
 */
function haveSomeRecipientsNoKey() {
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false &&
				processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false) {
			return true;
		}
	}
	return false;
}

/*
 * Checks if some recipients have a PGP key.
 * Returns true if at least one recipient has a PGP key.
 */
function haveSomeRecipientsPGP() {
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == true || processedRecipients[i].isPGPVVV == true) {
			return true;
		}
	}
	return false;
}

/*
 * Checks if some recipients have an S/MIME certificate.
 * Returns true if at least one recipient has an S/MIME certificate.
 */
function haveSomeRecipientsSMIME() {
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true) {
			return true;
		}
	}
	return false;
}

/*
 * Checks if some recipients have only a PGP key.
 * Returns true if at least one recipient has only a PGP key (and no S/MIME certificate).
 */
function haveSomeRecipientsOnlyPGP() {
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if ((processedRecipients[i].isPGPAvailable == true || processedRecipients[i].isPGPVVV == true) && (processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false)) {
			return true;
		}
	}
	return false;
}

/*
 * Checks if some recipients have only an S/MIME certificate.
 * Returns true if at least one recipient has only an S/MIME certificate (and no PGP key).
 */
function haveSomeRecipientsOnlySMIME() {
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if ((processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true) && (processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false)) {
			return true;
		}
	}
	return false;
}

/*
 * Returns all recipients with at least a PGP key.
 */
function getAllRecipientsWithPGP() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == true || processedRecipients[i].isPGPVVV == true) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}

/*
 * Returns all recipients with no PGP key.
 */
function getAllRecipientsWithNoPGP() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}

/*
 * Returns all recipients with at least an S/MIME certificate.
 */
function getAllRecipientsWithSMIME() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}

/*
 * Returns all recipients with no S/MIME certificate.
 */
function getAllRecipientsWithNoSMIME() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}

/*
 * Returns all recipients with only an S/MIME certificate (and no PGP key).
 */
function getAllRecipientsWithSMIMEOnly() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if ((processedRecipients[i].isSMIMEAvailable == true || processedRecipients[i].isSMIMEVVV == true) && (processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false)) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}

/*
 * Returns all recipients without any key (no PGP, no S/MIME).
 */
function getAllRecipientsWithNoKey() {
	let result = [];
	let processedRecipients = recipientsModel.processedRecipients;
	for(let i=0; i<processedRecipients.length; i++) {
		if (processedRecipients[i].isSMIMEAvailable == false && processedRecipients[i].isSMIMEVVV == false && processedRecipients[i].isPGPAvailable == false && processedRecipients[i].isPGPVVV == false) {
			result.push(processedRecipients[i]);
		}
	}
	return result;
}



function duplicateMail(numberOfMails, recipientGroupMail1, recipientGroupMail2, recipientGroupMail3) {
  Application.console.log("duplicateMailStart");
	let recipientsMail_1 = [];
	let recipientsMail_2 = [];
	let recipientsMail_3 = [];
	if (recipientGroupMail1 == "pgpGroup") {
		recipientsMail_1 = getAllRecipientsWithPGP();
	} else if (recipientGroupMail1 == "nopgpGroup") {
		recipientsMail_1 = getAllRecipientsWithNoPGP();
	} else if (recipientGroupMail1 == "smimeGroup") {
		recipientsMail_1 = getAllRecipientsWithSMIME();
	} else if (recipientGroupMail1 == "nosmimeGroup") {
		recipientsMail_1 = getAllRecipientsWithNoSMIME();
	} else if (recipientGroupMail1 == "smimeOnlyGroup") {
		recipientsMail_1 = getAllRecipientsWithSMIMEOnly();
	} else if (recipientGroupMail1 == "nokeyGroup") {
		recipientsMail_1 = getAllRecipientsWithNoKey();
	}
	if (recipientGroupMail2 == "pgpGroup") {
		recipientsMail_2 = getAllRecipientsWithPGP();
	} else if (recipientGroupMail2 == "nopgpGroup") {
		recipientsMail_2 = getAllRecipientsWithNoPGP();
	} else if (recipientGroupMail2 == "smimeGroup") {
		recipientsMail_2 = getAllRecipientsWithSMIME();
	} else if (recipientGroupMail2 == "nosmimeGroup") {
		recipientsMail_2 = getAllRecipientsWithNoSMIME();
	} else if (recipientGroupMail2 == "smimeOnlyGroup") {
		recipientsMail_2 = getAllRecipientsWithSMIMEOnly();
	} else if (recipientGroupMail2 == "nokeyGroup") {
		recipientsMail_2 = getAllRecipientsWithNoKey();
	}
	if (recipientGroupMail3 == "pgpGroup") {
		recipientsMail_3 = getAllRecipientsWithPGP();
	} else if (recipientGroupMail3 == "nopgpGroup") {
		recipientsMail_3 = getAllRecipientsWithNoPGP();
	} else if (recipientGroupMail3 == "smimeGroup") {
		recipientsMail_3 = getAllRecipientsWithSMIME();
	} else if (recipientGroupMail3 == "nosmimeGroup") {
		recipientsMail_3 = getAllRecipientsWithNoSMIME();
	} else if (recipientGroupMail3 == "smimeOnlyGroup") {
		recipientsMail_3 = getAllRecipientsWithSMIMEOnly();
	} else if (recipientGroupMail3 == "nokeyGroup") {
		recipientsMail_3 = getAllRecipientsWithNoKey();
	}

	Application.console.log("sender address: "+senderKeyInfo.address);

	let to = gMsgCompose.compFields.to;
	let toArray = to.split(", ");
	let cc = gMsgCompose.compFields.cc;
	let ccArray = cc.split(", ");
	let bcc = gMsgCompose.compFields.bcc;
	let bccArray = bcc.split(", ");

	newComposeWindow(recipientsMail_1, toArray, ccArray, bccArray);
	newComposeWindow(recipientsMail_2, toArray, ccArray, bccArray);
	if (recipientGroupMail3 != "") {
		newComposeWindow(recipientsMail_3, toArray, ccArray, bccArray);
	}
  Application.console.log("duplicateMailEnd");
}

/*
 * Opens a new composer window with the same sender identity, subject, body, and attachments as the
 * original composer window and with the given recipients addresses.
 */
function newComposeWindow(recipients, toArray, ccArray, bccArray) {

	let editor = gMsgCompose.editor;
	//Application.console.log("body, plain, 4: "+editor.outputToString('text/plain', 4));
	//Application.console.log("body, html, 2: "+editor.outputToString('text/html', 2));
	//Application.console.log("body, html, 8: "+editor.outputToString('text/html', 8));


	let msgComposeParams = Components.classes["@mozilla.org/messengercompose/composeparams;1"].createInstance(Components.interfaces.nsIMsgComposeParams);
	let compFields = Components.classes["@mozilla.org/messengercompose/composefields;1"].createInstance(Components.interfaces.nsIMsgCompFields);


	// set recipients addresses for 2nd e-mail
	var newTo = searchRecipients(toArray, recipients);
	compFields.to = newTo;

	var newCC = searchRecipients(ccArray, recipients);
	compFields.cc = newCC;

	var newBCC = searchRecipients(bccArray, recipients);
	compFields.bcc = newBCC;

	// set subject
	compFields.subject = getOriginalSubject();

	// set attachments
	var attachments = getOriginalAttachments();
	for(var i=0; i<attachments.length; i++) {
		compFields.addAttachment(attachments[i]);
	}

	// set mail body
	if (gMsgCompose.composeHTML) {
		Application.console.log("body, html, 516: "+editor.outputToString('text/html', 516));
		compFields.body = editor.outputToString('text/html', 516);
	} else {
		compFields.body = editor.outputToString('text/plain', 4);
	}

	msgComposeParams.composeFields = compFields;
	// set sender identity
	msgComposeParams.identity = gMsgCompose.identity;

	var msgComposeService =
		Components.classes["@mozilla.org/messengercompose;1"]
		.getService(Components.interfaces.nsIMsgComposeService);

	msgComposeService.OpenComposeWindowWithParams(null, msgComposeParams);
}

/*
 * Returns the subject from the original composer window.
 */
function getOriginalSubject() {
	return composerDocument.getElementById("msgSubject").value;
}

/*
 * Returns the attachments from the original composer window as an array.
 */
function getOriginalAttachments() {
	let attachments = [];
	let attachmentBucket = composerDocument.getElementById("attachmentBucket");
	for (let i=0; i<attachmentBucket.childNodes.length; i++) {
		let attachment = attachmentBucket.childNodes[i].attachment;
		if (attachment) {
			attachments.push(attachment);
		}
	}
	return attachments;
}

/*
 * Searches those email addresses that are in both arrays and
 * appends them to a comma-separated string.
 */
function searchRecipients(emailArray, recipients) {
	let newEmailStr = "";
	for (var i=0; i<emailArray.length; i++) {
		for (var k=0; k<recipients.length; k++) {
			if (emailArray[i] == recipients[k].email) {
				newEmailStr = newEmailStr + emailArray[i] + ", ";
			}
		}
	}
	if (newEmailStr.endsWith(", ")) {
		newEmailStr = newEmailStr.substring(0, newEmailStr.length-2);
	}
	return newEmailStr;
}

/*
 * Adds a recommendation text to the current e-mail body. The text will be inserted at cursor position.
 */
function addRecommendationText(keytype) {
	var editor = gMsgCompose.editor;
	var html_editor = editor.QueryInterface(Components.interfaces.nsIHTMLEditor);
	var keyTypeText = "";
	if (keytype == "1") {
		keyTypeText = "einen PGP-Schlüssel";
	} else if (keytype == "2") {
		keyTypeText = "ein S/MIME-Zertifikat";
	} else if (keytype == "3") {
		keyTypeText = "einen PGP-Schlüssel oder ein S/MIME-Zertifikat";
	}
	html_editor.insertHTML("<br/><br/>Leider konnte ich Dir keine verschlüsselte E-Mail senden. <br/>Schau Dir doch mal <a href=\"https://keys4all.de\">Keys4All</a> an. Dort erfährst Du, wie Du Dir "+keyTypeText+" besorgen kannst, damit wir in Zukunft verschlüsselte Nachrichten austauschen können!");

}

function openEncryptionPortal() {
  window.parent.MWTool.openTab("chrome://vvv-addon/content/ui/index.html");
}

function closeVVViFrame() {
	composerDocument.getElementById("button-send").setAttribute("disabled", "");
	//composerDocument.getElementById("iframe-vvv").setAttribute("hidden", "true");
	composerDocument.getElementById("iframe-vvv").setAttribute("width", "0");
	composerDocument.getElementById("iframe-vvv").setAttribute("height", "0");
	composerDocument.getElementById("iframe-vvv").setAttribute("style", "width:0;height:0;border: 0;border: none; visibility: hidden; display: none;");
}

/*
setTimeout(function () {
  var eventForParent = new CustomEvent('vvv-mail', {});
  var parentWindow = window.parent;//top;
  parentWindow.addressOnChangeVVV();
  //parentWindow.document.dispatchEvent(eventForParent);
  Application.console.log("Test");
}, 500);
*/

setTimeout(showRecommendations(), 500);
