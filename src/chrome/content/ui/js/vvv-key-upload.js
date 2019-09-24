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

Components.utils.import("resource://gre/modules/osfile.jsm");
Components.utils.import("resource://gre/modules/AddonManager.jsm");

const BASE_URL = "https://ox.keys4all-test.de";
const APPSUITE_PATH = "/appsuite/api/oxguard";

const FILENAME_PUBLISHED_KEYS = "vvv-published-keys.json";

var extensionPath;

var session;
var jSessionIdCookie;
var openXChangeSecretCookie;

var keyId;

var jsonPublishedKeys = null;

var loginResponse;
var uploadResponse;


function processKeyUpload(username, password, asciiArmoredKey, deferred) {

	loginResponse = null;
	uploadResponse = null;

	var loginCompleted = $.Deferred();
	login(username, password, loginCompleted);

	$.when(loginCompleted).done(function() {
		if (loginResponse.error == null) {
			var uploadCompleted = $.Deferred();
			upload(asciiArmoredKey, uploadCompleted);

			$.when(uploadCompleted).done(function() {
				var logoutCompleted = $.Deferred();
				logout(logoutCompleted);

				$.when(logoutCompleted).done(function() {
					deferred.resolve();
				});
			});
		} else {
			deferred.resolve();
		}
	});

	$.when(deferred).done(function(){
    	// do nothing
    })
}

function processKeyDelete(username, password, deferred) {

	loginResponse = null;
	uploadResponse = null;

	var loginCompleted = $.Deferred();
	login(username, password, loginCompleted);

	$.when(loginCompleted).done(function() {
		if (loginResponse.error == null) {
			var getKeyIdCompleted = $.Deferred();
			getKeyId(getKeyIdCompleted);

			$.when(getKeyIdCompleted).done(function() {
				var deleteCompleted = $.Deferred();
				deleteKey(deleteCompleted);

				$.when(deleteCompleted).done(function() {
					var logoutCompleted = $.Deferred();
					logout(logoutCompleted);

					$.when(logoutCompleted).done(function() {
						deferred.resolve();
					});
				});
			});
		} else {
			deferred.resolve();
		}
	});

	$.when(deferred).done(function(){
    	// do nothing
    })
}




function login(username, password, deferred) {
	var authId = generateUUID();
	Application.console.log("authId: "+authId);
	Application.console.log("username: "+username);
	Application.console.log("password: "+password);


	var loginPath = "/ajax/login?action=login&modules=true&client=vvv-addon&authId="+authId;

	var formData = new FormData();
	formData.append('name', username);
	formData.append('password', password);

	var jqxhr = $.ajax({
		url: BASE_URL + loginPath,
		dataType: 'json',
		cache: false, // important for IE support!
		type: 'POST',
		data: $.param({name: username, password: password}),
		cache: false,
		contentType: "application/x-www-form-urlencoded",
		processData: true
	})

	.done(function(data, textStatus, jqXHR){
		loginResponse = data;

		Application.console.log(JSON.stringify(data));
		Application.console.log("Login: "+textStatus);

		session = data.session;
		Application.console.log("session: "+session);

		var headers = jqXHR.getAllResponseHeaders();
		//Application.console.log("Headers: "+headers);
		var headerFields = headers.split("\r\n");
		if (headerFields.length == 0) {
			headerFields = headers.split("\r");
			if (headerFields.length == 0) {
				headerFields = headers.split("\n");
			}
		}
		if (headerFields.length > 0) {
			for (var i=0; i<headerFields.length; i++) {
				//Application.console.log("Header: "+headerFields[i]);
				if(headerFields[i].startsWith("Set-Cookie:")) {
					var splitHeader = headerFields[i].split(" ");
					for (var k=0; k<splitHeader.length; k++) {
						//Application.console.log("splitHeader[k]: "+splitHeader[k]);
						if (splitHeader[k].startsWith("JSESSIONID")) {
							jSessionIdCookie = splitHeader[k];
							if (jSessionIdCookie.endsWith(";")) {
								jSessionIdCookie = jSessionIdCookie.substring(0, jSessionIdCookie.length-1);
							}
							Application.console.log("jSessionIdCookie: "+jSessionIdCookie);
						} else if (splitHeader[k].indexOf("open-xchange-secret") >= 0) {
							openXChangeSecretCookie = splitHeader[k].substring(splitHeader[k].indexOf("open-xchange-secret"), splitHeader[k].length);
							if (openXChangeSecretCookie.endsWith(";")) {
								openXChangeSecretCookie = openXChangeSecretCookie.substring(0, openXChangeSecretCookie.length-1);
							}
							Application.console.log("openXChangeSecretCookie: "+openXChangeSecretCookie);
						}
					}
				}
			}
		}
		deferred.resolve();

	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		Application.console.log("Login failed. textStatus:" + textStatus + ", errorThrown: " + errorThrown);
		deferred.reject("Login error: "+textStatus);
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}

function logout(deferred) {
	var logoutPath = "/ajax/login?action=logout&session="+session;

	var jqxhr = $.ajax({
		url: BASE_URL + logoutPath,
		cache: false, // important for IE support!
		type: 'GET',
		cache: false,
		beforeSend: function (jqXHR) {jqXHR.setRequestHeader('Cookie', jSessionIdCookie + '; ' + openXChangeSecretCookie);},
		processData: false
	})

	.done(function(data, textStatus, jqXHR){
		Application.console.log("Logout: "+textStatus);
		session = "";
		jSessionIdCookie = "";
		openXChangeSecretCookie = "";
		deferred.resolve();
	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		Application.console.log("Logout failed. textStatus:" + textStatus + ", errorThrown: " + errorThrown);
		deferred.reject("Logout error: "+textStatus);
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}

function upload(asciiArmoredPublicKey, deferred) {
	var uploadPath = "/keys?action=upload&session="+session;

	var boundary = this.generateBoundary();

	var uploadData = "--"+boundary+"\r\n" + "Content-Disposition: form-data; name=\"key\"" + "\r\n" + "\r\n" + asciiArmoredPublicKey + "\r\n" + "--" + boundary;

	//Application.console.log(uploadData);

	var jqxhr = $.ajax({
		url: BASE_URL + APPSUITE_PATH + uploadPath,
		cache: false, // important for IE support!
		type: 'POST',
		data: uploadData,
		cache: false,
		beforeSend: function (jqXHR) {jqXHR.setRequestHeader('Cookie', jSessionIdCookie + '; ' + openXChangeSecretCookie);},
		contentType: "multipart/form-data; boundary=" + boundary,
		processData: false
	})

	.done(function(data, textStatus, jqXHR){
		uploadResponse = data;
		Application.console.log("Upload: "+textStatus);
		//Application.console.log(JSON.stringify(data));
		deferred.resolve();
	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		Application.console.log("Upload failed. textStatus:" + textStatus + ", errorThrown: " + errorThrown);
		deferred.reject("Upload error: "+textStatus);
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}

function getKeyId(deferred) {
	var path = "/keys?action=getKey&session="+session+"&keyType=public";

	var jqxhr = $.ajax({
		url: BASE_URL + APPSUITE_PATH + path,
		dataType: 'text',
		cache: false, // important for IE support!
		type: 'POST',
		cache: false,
		beforeSend: function (jqXHR) {jqXHR.setRequestHeader('Cookie', jSessionIdCookie + '; ' + openXChangeSecretCookie);},
		processData: false
	})

	.done(function(data, textStatus, jqXHR){
		Application.console.log(data);

		/* parse json response manually since Javascript's JSON parser
		  cannot handle BigInteger values correctly. */
		var startIndex = data.indexOf("\"masterKey\":true");
		var idStartIndex = data.indexOf("\"id\":", startIndex);
		var idEndIndex = data.indexOf("},", idStartIndex);

		keyId = data.substring(idStartIndex+5, idEndIndex);
		Application.console.log("keyId: "+keyId);

		deferred.resolve();

	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		Application.console.log("GetKeyId failed. textStatus:" + textStatus + ", errorThrown: " + errorThrown);
		deferred.reject("GetKeyId error: "+textStatus);
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}

function deleteKey(deferred) {
	if (keyId === null || keyId === "") {
		Application.console.log("Delete not possible. KeyId is not set.");
		deferred.resolve();
		return;
	}
	var deletePath = "/keys?action=delete&session="+session+"&keyid="+keyId;
	Application.console.log("Delete path: "+deletePath);

	var jqxhr = $.ajax({
		url: BASE_URL + APPSUITE_PATH + deletePath,
		cache: false, // important for IE support!
		type: 'POST',
		cache: false,
		beforeSend: function (jqXHR) {jqXHR.setRequestHeader('Cookie', jSessionIdCookie + '; ' + openXChangeSecretCookie);},
		processData: false
	})

	.done(function(data, textStatus, jqXHR){
		//Application.console.log(JSON.stringify(data));
		Application.console.log("Delete: "+textStatus);

		deferred.resolve();

	})
	.fail(function(jqXHR, textStatus, errorThrown) {
		Application.console.log("Delete failed. textStatus:" + textStatus + ", errorThrown: " + errorThrown);
		deferred.reject("Delete error: "+textStatus);
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}


/* ----  Helper functions ---- */

function generateUUID () { // Public Domain/MIT
	var d = new Date().getTime();
	if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
		d += performance.now(); //use high-precision timer if available
	}
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
		var r = (d + Math.random() * 16) % 16 | 0;
		d = Math.floor(d / 16);
		return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
	});
}

function generateBoundary() {
    return "AJAX-----------------------" + (new Date).getTime();
}

function getExtensionPath(deferred) {
	AddonManager.getAddonByID("vvv-addon@sit.fraunhofer.de", function(addon) {
		Application.console.log("Addon: "+addon);
		var uri = addon.getResourceURI(".");
		extensionPath = uri.path;

		if(CommonUtils.getOS() === "WINNT") {
			if(extensionPath[0] === '/') {
				extensionPath = extensionPath.substring(1);
				extensionPath = extensionPath.replace(/\//g, "\\");
			}
		}


		Application.console.log("URI: "+extensionPath);
		deferred.resolve();
	});
	$.when(deferred).done(function(){
    	// do nothing
    })
}


/* ------------------------------------------- */



function readJSONFilePublishedKeys(deferred) {
	var file = extensionPath + "..\\" + FILENAME_PUBLISHED_KEYS;
	Application.console.log("[readJSONFilePublishedKeys] File path: "+file);
	let promise = OS.File.exists(file);

	let newPromise = promise.then(function onFulfill(aExists) {
		if (aExists) {
			Application.console.log("File Found!");
			promise = OS.File.read(file)
			promise = promise.then(function onSuccess(array) {
				let decoder = new TextDecoder();
				let text = decoder.decode(array);
				Application.console.log(text);
				jsonPublishedKeys = JSON.parse(text);
				Application.console.log(JSON.stringify(jsonPublishedKeys));
				deferred.resolve();
			});
		} else {
			Application.console.log("File not found!");
			deferred.resolve();
		}
	});

	// Unexpected errors should always be reported at the end of a promise chain.
	let lastPromise = newPromise.then(null, Components.utils.reportError);

	$.when(deferred).done(function(){
    	// do nothing
    })
}

function writeJSONFilePublishedKeys(deferred) {

	var file = extensionPath + "..\\" + FILENAME_PUBLISHED_KEYS;
	Application.console.log("[writeJSONFilePublishedKeys] File path: "+file);

	var text = JSON.stringify(jsonPublishedKeys);
	let encoder = new TextEncoder();
	let array = encoder.encode(text);
	let promise = OS.File.writeAtomic(file, array, {});
	promise = promise.then(function onSuccess(array) {
		deferred.resolve();
	});

	$.when(deferred).done(function(){
    	// do nothing
    })
}

function isKeyPublished(email, keyType, fingerprint) {
	Application.console.log("isKeyPublished: "+email+" / "+keyType+" / "+fingerprint);

	if (jsonPublishedKeys === null) {
		return false;
	}

	let accounts = jsonPublishedKeys.accounts;
	if (accounts != null) {
		for (var i=0; i<accounts.length; i++) {
			let accountEmail = accounts[i].email;
			if (email === accountEmail) {
				Application.console.log("email match");
				let publishedKeys = accounts[i].publishedKeys;
				for (var k=0; k<publishedKeys.length; k++) {
					Application.console.log("type: "+publishedKeys[k].type);
					Application.console.log("fingerprint: "+publishedKeys[k].fingerprint);
					if (publishedKeys[k].type === keyType && publishedKeys[k].fingerprint === fingerprint) {
						Application.console.log("type and fingerprint match");
						return true;
					}
				}
			}
		}
	}
	return false;
}

function isPGPKeyPublished(email, keyType, pgpData) {
	Application.console.log("isPGPKeyPublished: "+email+" / "+keyType);

	if (jsonPublishedKeys === null) {
		return -1;
	}

	let accounts = jsonPublishedKeys.accounts;
	if (accounts != null) {
		for (var i=0; i<accounts.length; i++) {
			let accountEmail = accounts[i].email;
			if (email === accountEmail) {
				Application.console.log("email match");
				let publishedKeys = accounts[i].publishedKeys;
				for (var k=0; k<publishedKeys.length; k++) {
					Application.console.log("type: "+publishedKeys[k].type);
					Application.console.log("fingerprint: "+publishedKeys[k].fingerprint);
					for (var m=0; m<pgpData.length; m++) {
						Application.console.log("originalFingerprint: "+pgpData[m].originalFingerprint);
						if (publishedKeys[k].type === keyType && publishedKeys[k].fingerprint === pgpData[m].originalFingerprint) {
							Application.console.log("type and fingerprint match");
							return m;
						}
					}

				}
			}
		}
	}
	return -1;
}

function addPublishedKeyToFile(email, keyType, fingerprint) {
	if (jsonPublishedKeys == null) {
		jsonPublishedKeys = {};
		jsonPublishedKeys.accounts = new Array();

		let publishedKeys = new Array();
		publishedKeys.push({
			"type":keyType,
			"fingerprint":fingerprint
		});
		jsonPublishedKeys.accounts.push({
			"email":email,
			"publishedKeys":publishedKeys
		});
	} else {
		if (jsonPublishedKeys.accounts == null) {
			jsonPublishedKeys.accounts = new Array();
		}
		var emailExists = false;
		var keyExists = false;
		for (var i=0; i<jsonPublishedKeys.accounts.length; i++) {
			if (jsonPublishedKeys.accounts[i].email === email) {
				emailExists = true;
				if (jsonPublishedKeys.accounts[i].publishedKeys === null) {
					jsonPublishedKeys.accounts[i].publishedKeys = new Array();
				}
				for (var k=0; k<jsonPublishedKeys.accounts[i].publishedKeys.length; k++) {
					if (jsonPublishedKeys.accounts[i].publishedKeys[k].type === keyType && jsonPublishedKeys.accounts[i].publishedKeys[k].fingerprint === fingerprint) {
						keyExists = true;
					}
				}
				if (!keyExists) {
					jsonPublishedKeys.accounts[i].publishedKeys.push({
						"type":keyType,
						"fingerprint":fingerprint
					});
				}
			}
		}
		if (!emailExists) {
			let publishedKeys = new Array();
			publishedKeys.push({
				"type":keyType,
				"fingerprint":fingerprint
			});
			jsonPublishedKeys.accounts.push({
				"email":email,
				"publishedKeys":publishedKeys
			});
		}
	}

	var writeCompleted = $.Deferred();
	writeJSONFilePublishedKeys(writeCompleted);
	$.when(writeCompleted).done(function() {
		Application.console.log("[addPublishedKeyToFile] JSON file 'vvv-published-keys.json' successfully modified!");
	});
}

function removePublishedKeyFromFile(email, keyType, fingerprint) {
	Application.console.log("[removePublishedKeyFromFile] email: "+email+", keyType: "+keyType+", fingerprint: "+fingerprint);
	if (jsonPublishedKeys != null && jsonPublishedKeys.accounts != null) {
		for (var i=0; i<jsonPublishedKeys.accounts.length; i++) {
			if (jsonPublishedKeys.accounts[i].email === email) {
				if (jsonPublishedKeys.accounts[i].publishedKeys != null) {
					for (var k=0; k<jsonPublishedKeys.accounts[i].publishedKeys.length; k++) {
						if (jsonPublishedKeys.accounts[i].publishedKeys[k].type === keyType && jsonPublishedKeys.accounts[i].publishedKeys[k].fingerprint === fingerprint) {
							delete jsonPublishedKeys.accounts[i].publishedKeys[k].type;
							delete jsonPublishedKeys.accounts[i].publishedKeys[k].fingerprint;
							jsonPublishedKeys.accounts[i].publishedKeys.splice(k, 1);
							if (jsonPublishedKeys.accounts[i].publishedKeys.length == 0) {
								delete jsonPublishedKeys.accounts[i].publishedKeys;
								delete jsonPublishedKeys.accounts[i].email;
								jsonPublishedKeys.accounts.splice(i, 1);
								if (jsonPublishedKeys.accounts.length == 0) {
									delete jsonPublishedKeys.accounts;
									delete jsonPublishedKeys;
								}
							}

							var writeCompleted = $.Deferred();
							writeJSONFilePublishedKeys(writeCompleted);
							$.when(writeCompleted).done(function() {
								Application.console.log("[removePublishedKeyFromFile] JSON file 'vvv-published-keys.json' successfully modified!");
							});
							return;
						}
					}
				}
			}
		}
	}
}
