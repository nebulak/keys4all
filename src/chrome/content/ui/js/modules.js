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
Components.utils.import("chrome://vvv-addon/content/ui/js/subprocess.jsm");

/**
 *  Logging Module
 * @module Logger
 */
var Logger = {
  _logLevel: 0,
  _logType: "console",
  /**
   * Private internal log function, use the following functions to log: trace, debug, info, warn, error
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   * @param {int} logLevel - LogLevel: 1 - 5. 0 = OFF
   */
  _log: function (logMessage, logLevel) {
    if( (logLevel >= this._logLevel) && (this._logLevel !== 0) ) {
      if(this._logType === "console") {
        var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
        var Application = Cc["@mozilla.org/steel/application;1"]
                        .getService(Ci.steelIApplication);
        Application.console.log(logMessage);
      }
    }
  },
  /**
   * Log messages with LogLevel=TRACE
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   */
  trace: function (logMessage) {
    this._log("TRACE: " + logMessage, 1);
  },
  /**
   * Log messages with LogLevel=DEBUG
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   */
  debug: function (logMessage) {
    this._log("DEBUG: " + logMessage, 2);
  },
  /**
   * Log messages with LogLevel=INFO
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   */
  info: function (logMessage) {
    this._log("INFO: " + logMessage, 3);
  },
  /**
   * Log messages with LogLevel=WARN
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   */
  warn: function (logMessage) {
    this._log("WARN: " + logMessage, 4);
  },
  /**
   * Log messages with LogLevel=ERROR
   * @function
   * @memberof module:Logger
   * @param {string} logMessage - The message to log.
   */
  error: function (logMessage) {
    this._log("ERROR: " + logMessage, 5);
  }
};



/* FakeLocalStorage needed by OpenPGP.js*/
var fakeLocalStorage = {
  _data       : {},
  setItem     : function(id, val) { return this._data[id] = String(val); },
  getItem     : function(id) { return this._data.hasOwnProperty(id) ? this._data[id] : null; },
  removeItem  : function(id) { return delete this._data[id]; },
  clear       : function() { return this._data = {}; }
};

/**
 *  HKPS Module for secure lookup of keys at a HKPS server
 * @module HKPS
 */
var HKPS = {
  /**
   * Looks up a key at a keyserver and calls the given callback function with the found keys as argument
   * @function
   * @memberof module:HKPS
   * @param {string} serverAddress - The keyserver address.
   * @param {string} searchString - The string to search: email/name or key-ID.
   * @param {bool} isKeyID - Set this to true if searchString is a key-ID.
   * @param {function} callback - Callback function which receives the armored PGP-key as string. If no key is found, the string is empty ("")
   */
  lookup: function (serverAddress, searchString, isKeyID, callback) {
    Logger.debug("HKPS.lookup");
    var queryURL = serverAddress + '/pks/lookup?op=get&options=mr&search=';
    if(isKeyID) {
      queryURL += '0x' + encodeURIComponent(searchString);
    } else {
      queryURL += encodeURIComponent(searchString);
    }
    //this.insecureFetch(queryURL, callback);
    this.secureFetch(queryURL, callback);
  },
  /**
  * sends HTTPS request **without** DNSSEC and DANE checks
  * @function
  * @memberof module:HKPS
  * @param {string} queryURL - The URL for the request.
  * @param {function} callback - Callback function to pass the result to.
  */
  insecureFetch: function (queryURL, callback) {
    Logger.debug("HKPS.insecureFetch");
    fetch("https://" + queryURL)
    .then(function(response) {
      if(response.status === 200) {
        return response.text();
      }
    })
    .then(function(publicKeys) {
      if(!publicKeys || publicKeys.indexOf('-----END PGP PUBLIC KEY BLOCK-----') <= 0) {
        callback("");
      }
      callback(publicKeys.trim());
    });
  },
  /**
  * sends HTTPS request **with** DNSSEC and DANE checks
  * @function
  * @memberof module:HKPS
  * @param {string} queryURL - The URL for the request.
  * @param {function} callback - Callback function to pass the result to.
  */
  secureFetch: function (queryURL, callback) {
    Logger.debug("HKPS.secureFetch");
    Application.console.log("secureFetch-URL: " + queryURL);
    //TODO:
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var subProcStdOut = "";
    var subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/SecureFetch");
    var workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('/'));

    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/SecureFetch.exe");
      workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('\\'));
    }

    Application.console.log("secureFetch-FilePath: " + subProcCommand);
    Application.console.log("secureFetch-work-dir: " + workDir);

    var subProcArgs = ['-dane', queryURL];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      workdir: workDir,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        var publicKeys = subProcStdOut;
        //TODO: delete ...
        Application.console.log("secureFetch-StdOut: " + publicKeys);
        if(!publicKeys) {
          callback("");
        }
        if(publicKeys.indexOf('-----END PGP PUBLIC KEY BLOCK-----') <= 0) {
          callback("");
        }
        callback(publicKeys.trim());
      }
    };
    var p = subprocess.call(subProcOptions);
    p.wait();
  },
  /**
   * Returns the HKP-server address for a domain, if there is an entry at the DNS-server of the provider.
   * @function
   * @memberof module:HKPS
   * @param {string} mailDomain - The domain of the mail provider
   * @param {function} callback - Callback function which receives the HKP-server address as string.
   */
  getVVVHKP: function(mailDomain, callback) {
    Logger.debug("HKPS.getVVVHKP");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var subProcStdOut = "";
    var subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/SecureFetch");
    var workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('/'));

    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/SecureFetch.exe");
      workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('\\'));
    }

    Application.console.log("getVVVHKP-FilePath: " + subProcCommand);
    Application.console.log("getVVVHKP-domain: " + mailDomain);
    Application.console.log("getVVVHKP-work-dir: " + workDir);

    var subProcArgs = ['-pgp', mailDomain];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      workdir: workDir,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        Application.console.log("getVVVHKP-Result: " + JSON.stringify(result));
        var parsedResult = subProcStdOut;

        if(parsedResult.indexOf('.') != -1)
        {
          callback(subProcStdOut);
        }
        else
        {
          callback("");
        }
      }
    };
    subprocess.call(subProcOptions);
  },
  lookupVVV: function () {
    //TODO: getVVVHKP, lookup
  }
};


/**
 * Stores info about a mail-account and it's keys
 * @constructor
 * @param {string} _email - The email address.
 * @param {bool} _isPGPAvailable - true, if a pgp-key is available for the address.
 * @param {object} _pgp_key - KeyInfo object containing info about the pgp key.
 * @param {bool} _isSMIMEAvailable - true, if a smime-key is available for the address.
 * @param {object} _smime_key - KeyInfo object containing info about the S/MIME key.
 */
var AccountKeyInfo = function(_email, _isPGPAvailable, _pgp_key, _isSMIMEAvailable, _smime_key){
  this.email = _email;
  this.isPGPAvailable = _isPGPAvailable;
  this.pgp_key = _pgp_key;
  this.isSMIMEAvailable = _isSMIMEAvailable;
  this.smime_key = _smime_key;
};

/**
 * Stores info about a key
 * @constructor
 * @param {string} _expiration_date - Expiration date as string or null.
 * @param {string} _key_id - Key ID.
 * @param {string} _fingerprint - Fingerprint of the key.
 * @param {bool} _isVVVRegistered - true, if the key is already registered at the provider.
 */
var KeyInfo = function (_expiration_date, _key_id, _fingerprint, _isVVVRegistered) {
  this.expiration_date = _expiration_date;
  this.key_id = _key_id;
  this.fingerprint = _fingerprint;
  this.isVVVRegistered = _isVVVRegistered;
};

/**
 * Stores info about a key for a recipient
 * @constructor
 * @param {string} _email - email as string.
 * @param {bool} _isPGPChecked - is pgp checked.
 * @param {bool} _isPGPAvailable - is pgp key available.
 * @param {bool} _isPGPVVV - is the pgp key's source a vvv-hkp-server.
 * @param {bool} _isSMIMEChecked - is smime checked.
 * @param {bool} _isSMIMEAvailable - is smime certificate available.
 * @param {bool} _isSMIMEVVV - is the smime certificate's source a vvv-ldap-server.
 * @param {string} _pgpKey - The PGP key.
 * @param {string} _smimeCert - The SMIME certificate.
 */
var RecipientKeyInfo = function (_email, _isPGPChecked, _isPGPAvailable, _isPGPVVV, _isSMIMEChecked, _isSMIMEAvailable, _isSMIMEVVV, _pgpKey, _smimeCert) {
  this.email = _email;
  this.isPGPChecked = _isPGPChecked;
  this.isPGPAvailable = _isPGPAvailable;
  this.isPGPVVV = _isPGPVVV;
  this.isSMIMEChecked = _isSMIMEChecked;
  this.isSMIMEAvailable = _isSMIMEAvailable;
  this.isSMIMEVVV = _isSMIMEVVV;
  this.pgpKey = _pgpKey;
  this.smimeCert = _smimeCert;
};


var KeyDiscoverer = {
  updateTime: 3600.000, //Time before updating key in seconds
  recipientsToProcess: [],
  recipientsInProgress: [],
  recipientsInQueue: 0,
  pgpRecipientsInQueue: 0,
  pgpRecipientsToProcess: [],
  pgpProcessedRecipients: [],
  smimeRecipientsInQueue: 0,
  smimeRecipientsToProcess: [],
  smimeProcessedRecipients: [],
  processedRecipients: [],
  pgpDomainKeyserverMap: {},
  smimeDomainKeyserverMap: {},
  callback: {},
  addRecipients: function(recipientsArray) {
    //TODO: multiple queues for pgp&smime
    //toprocess -> processed
    //    processSMIME -> processedSMIME
    //    processPGP -> processedPGP
    //                                    |_:->processed
	  for(var i=0; i<recipientsArray.length; i++) {
      //check if recipient is already in queue
      if(this.recipientsToProcess.indexOf(recipientsArray[i]) === -1 &&
         this.isRecipientProcessed(recipientsArray[i]) === false
      )
      {
        this.recipientsToProcess.push(recipientsArray[i]);
        //use recipientsInProgress-array to immediately show email address in table
        this.recipientsInProgress.push(recipientsArray[i]);

        //check if pgp recipient is already processed
        if(this.isPgpRecipientProcessed(recipientsArray[i]) == false)
        {
          this.pgpRecipientsInQueue++;
          this.getKeyForRecipient(recipientsArray[i], this.onPgpRecipientProcessed);
        }


        //check if smime recipient is already processed
        if(this.isSmimeRecipientProcessed(recipientsArray[i]) == false)
        {
          this.smimeRecipientsInQueue++;
          this.getCertForRecipient(recipientsArray[i], this.onSmimeRecipientProcessed);
        }

        //TODO: check if it works without next line
        //this.callback(this.recipientsInProgress, this.processedRecipients);

      }
    }
  },
  getCertForRecipient: function(email, callback) {
    Application.console.log("getCertForRecipient: email: " + email);
    //search VVV-pgp
    var mailDomain = email.substring(email.indexOf("@") + 1);
    var ldapServer = "";
    var self = this;
    Application.console.log("getCertForRecipient: mailDomain: " + mailDomain);

    //check
    //  - if vvv-ldap-server exists
    //  - if smime-ldap-address is in cache
    if(this.smimeDomainKeyserverMap[mailDomain] === undefined)
    {
      LDAPTool.getVVVLDAP(mailDomain, function(ldap_url) {
        Application.console.log("getCertForRecipient: ldap_url: " + ldap_url);
        //VVV-server exists
        if(ldap_url !== "" && ldap_url !== undefined) {
          self.smimeDomainKeyserverMap[mailDomain] = ldap_url;
          var keyServer = self.smimeDomainKeyserverMap[mailDomain];
          var keyFromCache = vvvKeyCache.getCert(email);
          //check if key is in cache
          if( keyFromCache != null)
          {
            if( vvvKeyCache.isUpdateNeeded(this.updateTime, keyFromCache) == false )
            {
              Application.console.log("using key from cache");
              //TODO: return
              var processedRecipient = this._cacheCert2KeyInfo(keyFromCache);
              self._cleanAfterSearchSMIME(email, processedRecipient);
            }
            else
            {
              Application.console.log("searching for key at ldap");
              LDAPTool.lookup(keyServer, email, function (cert) {
                if(cert !== "")
                {
                  if(cert.indexOf("userCertificate;binary: ") === -1)
                  {
                    Application.console.log("No cert found at ldap");
                    //TODO: return
                    return "";
                  }

                  //Import Cert
                  var cert_hex = cert.split("userCertificate;binary: ")[1];
                  cert_hex = cert_hex.toLowerCase();
                  var cert_bytes = CommonUtils.hexToByte(cert_hex);
                  Application.console.log("Adding cert to TB");
                  var cert_b64 = CommonUtils.hexToBase64(cert_hex);
                  //var cert_b64 = CommonUtils.byteArrayToB64(cert_bytes);
                  CertDBManager.addCert(cert_b64);
                  Application.console.log("Added cert to TB");

                  //Save to cache
                  //var cert_hasher = new jsSHA(cert_hex, "HEX");
                  //var cert_hash = cert_hasher.getHash("SHA-256", "HEX", 1, {outputUpper : true});
                  var cert_hash = sha256('cert_b64');
                  vvvKeyCache.saveCert(email, "vvv-server", cert_hash);

                  if(self.isSmimeRecipientProcessed(email) === false) {
                    Application.console.log("SMIME Recipient processed: VVV-SMIME");
                    var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, true, null, null);
                    self._cleanAfterSearchSMIME(email, processedRecipient);
                  }
                  Application.console.log("SMIME Recipient processed: No VVV-SMIME");
                }
                else
                {
                    Application.console.log("SMIME Recipient VVV_LDAP-Info: No cert found");
                    //TODO: save to cache

                    //check for local cert
                    if(CertDBManager.isCertAvailable(email)) {
                      if(self.isSmimeRecipientProcessed(email) === false) {
                        var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, false, null, null);
                        self._cleanAfterSearchSMIME(email, processedRecipient);
                      }
                    } else {
                      //TODO: save to cache

                      //No certificate
                      if(self.isSmimeRecipientProcessed(email) === false) {
                        var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, false, false, null, null);
                        self._cleanAfterSearchSMIME(email, processedRecipient);
                      }
                    }
                }
              });
            }
          }
          else // key is not in cache, search vvv-ldap and local
          {
            Application.console.log("searching for cert at ldap");
            LDAPTool.lookup(keyServer, email, function (cert) {

              if(cert.indexOf("userCertificate;binary: ") === -1)
              {
                Application.console.log("Found no cert at ldap");

                //get local cert
                if(CertDBManager.isCertAvailable(email) == true) {
                  //TODO: save to cache
                  if(self.isSmimeRecipientProcessed(email) === false) {
                    //TODO: save to cache
                    var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, false, null, null);
                    self._cleanAfterSearchSMIME(email, processedRecipient);
                  }
                }
                else {
                  //No certificate
                  if(self.isSmimeRecipientProcessed(email) === false) {
                    var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, false, false, null, null);
                    self._cleanAfterSearchSMIME(email, processedRecipient);
                  }
                }
              }
              else //Import Cert from VVV-LDAP
              {
                //Import Cert
                Application.console.log("Found cert at ldap");
                var cert_hex = cert.split("userCertificate;binary: ")[1];
                cert_hex = cert_hex.toLowerCase();
                Application.console.log("Cert: \n" + cert_hex);
                var cert_bytes = CommonUtils.hexToByte(cert_hex);

                Application.console.log("Adding cert to TB");
                var cert_b64 = CommonUtils.hexToBase64(cert_hex);
                //var cert_b64 = CommonUtils.byteArrayToB64(cert_bytes);
                CertDBManager.addCert(cert_b64);
                Application.console.log("Added cert to TB");

                //Save to cache
                var cert_hash = sha256('cert_b64');
                vvvKeyCache.saveCert(email, "vvv-server", cert_hash);

                if(self.isSmimeRecipientProcessed(email) === false) {
                  var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, true, null, null);
                  self._cleanAfterSearchSMIME(email, processedRecipient);
                }
              }
            });
          }
        }
        else //VVV-server does not exist
        {
          // search local

          //check for local cert
          if(CertDBManager.isCertAvailable(email)) {
            if(self.isSmimeRecipientProcessed(email) === false) {
              //TODO: save to cache
              var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, false, null, null);
              self._cleanAfterSearchSMIME(email, processedRecipient);
            }
          } else {
            //TODO: save to cache

            //No certificate
            if(self.isSmimeRecipientProcessed(email) === false) {
              var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, false, false, null, null);
              self._cleanAfterSearchSMIME(email, processedRecipient);
            }
          }
        }
      });

    }
    else //ldap-server address is in cache
    {
      var keyServer = self.smimeDomainKeyserverMap[mailDomain];
      var keyFromCache = vvvKeyCache.getCert(email);
      //check if key is in cache
      if( keyFromCache != null)
      {
        if( vvvKeyCache.isUpdateNeeded(this.updateTime, keyFromCache) == false )
        {
          Application.console.log("using key from cache");
          //TODO: return
          var processedRecipient = this._cacheCert2KeyInfo(keyFromCache);
          self._cleanAfterSearchSMIME(email, processedRecipient);
        }
        else
        {
          Application.console.log("searching for key at ldap");
          LDAPTool.lookup(keyServer, email, function (cert) {
            if(cert !== "")
            {
              if(cert.indexOf("userCertificate;binary: ") === -1)
              {
                //TODO: return
                return "";
              }

              //Import Cert
              var cert_hex = cert.split("userCertificate;binary: ")[1];
              cert_hex = cert_hex.toLowerCase();
              var cert_bytes = CommonUtils.hexToByte(cert_hex);
              Application.console.log("Adding cert to TB");
              var cert_b64 = CommonUtils.hexToBase64(cert_hex);
              //var cert_b64 = CommonUtils.byteArrayToB64(cert_bytes);
              CertDBManager.addCert(cert_b64);
              Application.console.log("Added cert to TB");

              //Save to cache
              //var cert_hasher = new jsSHA(cert_hex, "HEX");
              //var cert_hash = cert_hasher.getHash("SHA-256", "HEX", 1, {outputUpper : true});
              var cert_hash = sha256('cert_b64');
              vvvKeyCache.saveCert(email, "vvv-server", cert_hash);

              if(self.isSmimeRecipientProcessed(email) === false) {
                var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, true, null, null);
                self._cleanAfterSearchSMIME(email, processedRecipient);
              }
            }
            else
            {
                //TODO: save to cache

                //check for local cert
                if(CertDBManager.isCertAvailable(email)) {
                  if(self.isSmimeRecipientProcessed(email) === false) {
                    var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, false, null, null);
                    self._cleanAfterSearchSMIME(email, processedRecipient);
                  }
                } else {
                  //TODO: save to cache

                  //No certificate
                  if(self.isSmimeRecipientProcessed(email) === false) {
                    var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, false, false, null, null);
                    self._cleanAfterSearchSMIME(email, processedRecipient);
                  }
                }
            }
          });
        }
      }
      else // key is not in cache, search vvv-ldap and local
      {
        Application.console.log("searching for cert at ldap");
        LDAPTool.lookup(keyServer, email, function (cert) {

          if(cert.indexOf("userCertificate;binary: ") === -1)
          {
            Application.console.log("Found no cert at ldap");

            //get local cert
            if(CertDBManager.isCertAvailable(email) == true) {
              if(self.isSmimeRecipientProcessed(email) === false) {
                //TODO: save to cache
                var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, false, null, null);
                self._cleanAfterSearchSMIME(email, processedRecipient);
              }
            }
            else {
              //No certificate
              if(self.isSmimeRecipientProcessed(email) === false) {
                var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, false, false, null, null);
                self._cleanAfterSearchSMIME(email, processedRecipient);
              }
            }
          }
          else //Import Cert from VVV-LDAP
          {
            //Import Cert
            Application.console.log("Found cert at ldap");
            var cert_hex = cert.split("userCertificate;binary: ")[1];
            cert_hex = cert_hex.toLowerCase();
            Application.console.log("Cert: \n" + cert_hex);
            var cert_bytes = CommonUtils.hexToByte(cert_hex);

            Application.console.log("Adding cert to TB");
            var cert_b64 = CommonUtils.hexToBase64(cert_hex);
            //var cert_b64 = CommonUtils.byteArrayToB64(cert_bytes);
            CertDBManager.addCert(cert_b64);
            Application.console.log("Added cert to TB");

            //Save to cache
            var cert_hash = sha256('cert_b64');
            vvvKeyCache.saveCert(email, "vvv-server", cert_hash);

            if(self.isSmimeRecipientProcessed(email) === false) {
              var processedRecipient = new RecipientKeyInfo(email, false, false, false, true, true, true, null, null);
              self._cleanAfterSearchSMIME(email, processedRecipient);
            }
          }
        });
      }
    }
  },
  getKeyForRecipient: function(email, callback) {
    //search VVV-pgp
    var mailDomain = email.substring(email.indexOf("@") + 1);
    var keyServer = "";
    var self = this;

    //check if pgp-keyserver-address is in cache
    //pgp-keyserver-address is in cache
    if(this.pgpDomainKeyserverMap[mailDomain] !== undefined)
    {
      keyServer = self.pgpDomainKeyserverMap[mailDomain];
      var keyFromCache = vvvKeyCache.getKey(email);
      //check if key is in cache
      if( keyFromCache != null)
      {
        if( vvvKeyCache.isUpdateNeeded(this.updateTime, keyFromCache) == false )
        {
          Application.console.log("using key from cache");
          var processedRecipient = this._cacheKey2KeyInfo(keyFromCache);
          self._cleanAfterSearchPGP(email, processedRecipient);
        }
        else
        {
          Application.console.log("searching for key at hkp");
          Application.console.log("getKeyForRecipient: HKPS.lookup: " + keyServer + ", " + email);
          HKPS.lookup(keyServer, email, false, function(pgpKey) {
            Application.console.log("PGP-Key: " + pgpKey);
            if(pgpKey !== "")
            {
              //import key
              GPGIPC.importKey(pgpKey, function(result) {});
              //save to cache
              var keys = KeyManager.getPublicKeys(email);
              if (keys.length !== 0) {
                if(keys[0] != "") {
                  var fingerprint = keys[0].primaryKey.getFingerprint();
                  vvvKeyCache.saveKey(email, "vvv-server", fingerprint);
                }
              }

              if(self.isPgpRecipientProcessed(email) === false) {
                //TODO: add SMIME check
                var processedRecipient = new RecipientKeyInfo(email, true, true, true, false, false, false, pgpKey, null);
                self._cleanAfterSearchPGP(email, processedRecipient);
              }
            }
            else
            {
                //search for local key
                var processedRecipient = self._localKey2KeyInfo(email);

                //save to cache
                if(processedRecipient.isPGPAvailable)
                {
                  var keys = KeyManager.getPublicKeys(email);
                  if (keys.length !== 0) {
                    if(keys[0] != "") {
                      var fingerprint = keys[0].primaryKey.getFingerprint();
                      vvvKeyCache.saveKey(email, "local", fingerprint);
                    }
                  }
                }
                else
                {
                  vvvKeyCache.saveKey(email, "not-found", "");
                }

                self._cleanAfterSearchPGP(email, processedRecipient);
            }
          });
        }
      }
      else
      {
        HKPS.lookup(keyServer, email, false, function(pgpKey) {
          Application.console.log("PGP-Key: " + pgpKey);
          if(pgpKey !== "")
          {
            //import key
            GPGIPC.importKey(pgpKey, function(d) {});
            //save to cache
            var keys = KeyManager.getPublicKeys(email);
            if (keys.length !== 0) {
              if(keys[0] != "") {
                var fingerprint = keys[0].primaryKey.getFingerprint();
                vvvKeyCache.saveKey(email, "vvv-server", fingerprint);
              }
            }

            if(self.isPgpRecipientProcessed(email) === false) {
              //TODO: add SMIME check
              var processedRecipient = new RecipientKeyInfo(email, true, true, true, false, false, false, pgpKey, null);
              self._cleanAfterSearchPGP(email, processedRecipient);
            }
          }
          else
          {
              //search for local key
              var processedRecipient = self._localKey2KeyInfo(email);

              //save to cache
              if(processedRecipient.isPGPAvailable)
              {
                var keys = KeyManager.getPublicKeys(email);
                if (keys.length !== 0) {
                  if(keys[0] != "") {
                    var fingerprint = keys[0].primaryKey.getFingerprint();
                    vvvKeyCache.saveKey(email, "local", fingerprint);
                  }
                }
              }
              else
              {
                vvvKeyCache.saveKey(email, "not-found", "");
              }

              self._cleanAfterSearchPGP(email, processedRecipient);
          }
        });
      }
    }
    else //pgp-keyserver address not in cache
    {
      var keyFromCache = vvvKeyCache.getKey(email);
      if( keyFromCache != null)
      {
        if( vvvKeyCache.isUpdateNeeded(this.updateTime, keyFromCache) == false )
        {
          var processedRecipient = this._cacheKey2KeyInfo(keyFromCache);
          Application.console.log("Recipient fdrom cache: " + JSON.stringify(processedRecipient));
          self._cleanAfterSearchPGP(email, processedRecipient);
        }
        else
        {
            HKPS.getVVVHKP(mailDomain, function(pgpServer) {
              if(pgpServer === "")
              {
                //TODO: search localPGPKeys
                if(self.isPgpRecipientProcessed(email)===false) {
                  //search for local pgp key
                  var processedRecipient=self._localKey2KeyInfo(email);

                  //save to cache
                  if(processedRecipient.isPGPAvailable)
                  {
                    var keys = KeyManager.getPublicKeys(email);
                    if (keys.length !== 0) {
                      if(keys[0] != "") {
                        var fingerprint = keys[0].primaryKey.getFingerprint();
                        vvvKeyCache.saveKey(email, "local", fingerprint);
                      }
                    }
                  }
                  else
                  {
                    vvvKeyCache.saveKey(email, "not-found", "");
                  }
                  self._cleanAfterSearchPGP(email, processedRecipient);
                }
              }
              else
              {
                keyServer = pgpServer;
                keyServer = keyServer.substring(0, keyServer.length - 1);

                //cache keyserver-address
                self.pgpDomainKeyserverMap[mailDomain] = keyServer;
                Application.console.log("Keyserver: " + keyServer);

                //search for vvv pgp key
                HKPS.lookup(keyServer, email, false, function(pgpKey) {
                  Application.console.log("PGP-Key: " + pgpKey);
                  if(pgpKey !== "")
                  {
                    //import key
                    GPGIPC.importKey(pgpKey, function(d) {});

                    //save to cache
                    var keys = KeyManager.getPublicKeys(email);
                    if (keys.length !== 0) {
                      if(keys[0] != "") {
                        var fingerprint = keys[0].primaryKey.getFingerprint();
                        vvvKeyCache.saveKey(email, "vvv-server", fingerprint);
                      }
                    }
                    //TODO: add SMIME check*/
                    var processedRecipient = new RecipientKeyInfo(email, true, true, true, false, false, false, pgpKey, null);
                    self._cleanAfterSearchPGP(email, processedRecipient);
                  }
                  else
                  {
                    if(self.isPgpRecipientProcessed(email)===false) {
                      //search for local pgp key
                      var processedRecipient = self._localKey2KeyInfo(email);
                      //save to cache
                      if(processedRecipient.isPGPAvailable)
                      {
                        var keys = KeyManager.getPublicKeys(email);
                        if (keys.length !== 0) {
                          if(keys[0] != "") {
                            var fingerprint = keys[0].primaryKey.getFingerprint();
                            vvvKeyCache.saveKey(email, "local", fingerprint);
                          }
                        }
                      }
                      else
                      {
                        vvvKeyCache.saveKey(email, "not-found", "");
                      }

                      self._cleanAfterSearchPGP(email, processedRecipient);
                    }
                  }
                });
              }
            });
        }
      }
      else
      {
        HKPS.getVVVHKP(mailDomain, function(pgpServer) {
          if(pgpServer === "")
          {
            //TODO: search localPGPKeys
            if(self.isPgpRecipientProcessed(email)===false) {
              //search for local pgp key
              var processedRecipient=self._localKey2KeyInfo(email);

              //save to cache
              if(processedRecipient.isPGPAvailable)
              {
                var keys = KeyManager.getPublicKeys(email);
                if (keys.length !== 0) {
                  if(keys[0] != "") {
                    var fingerprint = keys[0].primaryKey.getFingerprint();
                    vvvKeyCache.saveKey(email, "local", fingerprint);
                  }
                }
              }
              else
              {
                vvvKeyCache.saveKey(email, "not-found", "");
              }
              self._cleanAfterSearchPGP(email, processedRecipient);
            }
          }
          else
          {
            keyServer = pgpServer;
            keyServer = keyServer.substring(0, keyServer.length - 1);

            //cache keyserver-address
            self.pgpDomainKeyserverMap[mailDomain] = keyServer;
            Application.console.log("Keyserver: " + keyServer);

            //search for vvv pgp key
            HKPS.lookup(keyServer, email, false, function(pgpKey) {
              Application.console.log("PGP-Key: " + pgpKey);
              if(pgpKey !== "")
              {
                //import key
                GPGIPC.importKey(pgpKey, function(d) {});

                //save to cache
                var keys = KeyManager.getPublicKeys(email);
                if (keys.length !== 0) {
                  if(keys[0] != "") {
                    var fingerprint = keys[0].primaryKey.getFingerprint();
                    vvvKeyCache.saveKey(email, "vvv-server", fingerprint);
                  }
                }

                if(self.isPgpRecipientProcessed(email) === false) {
                  //TODO: add SMIME check
                  var processedRecipient = new RecipientKeyInfo(email, true, true, true, false, false, false, pgpKey, null);
                  self._cleanAfterSearchPGP(email, processedRecipient);
                }
              }
              else
              {
                if(self.isPgpRecipientProcessed(email)===false) {
                  //search for local pgp key
                  var processedRecipient = self._localKey2KeyInfo(email);
                  //save to cache
                  if(processedRecipient.isPGPAvailable)
                  {
                    var keys = KeyManager.getPublicKeys(email);
                    if (keys.length !== 0) {
                      if(keys[0] != "") {
                        var fingerprint = keys[0].primaryKey.getFingerprint();
                        vvvKeyCache.saveKey(email, "local", fingerprint);
                      }
                    }
                  }
                  else
                  {
                    vvvKeyCache.saveKey(email, "not-found", "");
                  }

                  self._cleanAfterSearchPGP(email, processedRecipient);
                }
              }
            });
          }
        });
      }
    }
  },
  isRecipientProcessed: function(email) {
    for(var i=0; i<this.processedRecipients.length; i++) {
      if(this.processedRecipients[i].email === email)
      {
        return true;
      }
    }
    return false;
  },
  isPgpRecipientProcessed: function(email) {
    for(var i=0; i<this.pgpProcessedRecipients.length; i++) {
      if(this.pgpProcessedRecipients[i].email === email)
      {
        return true;
      }
    }
    return false;
  },
  isSmimeRecipientProcessed: function(email) {
    for(var i=0; i<this.smimeProcessedRecipients.length; i++) {
      if(this.smimeProcessedRecipients[i].email === email)
      {
        return true;
      }
    }
    return false;
  },
  deleteRecipientToProcess: function(email) {
    for(var i=0; i<this.recipientsToProcess.length; i++) {
      if(this.recipientsToProcess[i] === email)
      {
        Application.console.log("\nDelete from queue: " + this.recipientsToProcess[i]);
        this.recipientsToProcess.splice(i, 1);

        return;
      }
    }
  },
  deletePgpRecipientToProcess: function(email) {
    var self = this;
    for(var i=0; i<self.pgpRecipientsToProcess.length; i++) {
      if(self.pgpRecipientsToProcess[i] === email)
      {
        Application.console.log("\nDelete from queue: " + self.recipientsToProcess[i]);
        self.pgpRecipientsToProcess.splice(i, 1);

        return;
      }
    }
  },
  deleteSmimeRecipientToProcess: function(email) {
    var self = this;
    for(var i=0; i<self.smimeRecipientsToProcess.length; i++) {
      if(self.smimeRecipientsToProcess[i] === email)
      {
        Application.console.log("\nDelete from queue: " + self.recipientsToProcess[i]);
        self.smimeRecipientsToProcess.splice(i, 1);

        return;
      }
    }
  },
  mergeProcessedRecipients: function() {
    var self = this;
    //get pgp processed recipients
    for(var i=0; i < self.pgpProcessedRecipients.length; i++)
    {
      var pgpRecipient = self.pgpProcessedRecipients[i];
      //check for same recipient in processed smime recipients list
      for(var j=0; j < self.smimeProcessedRecipients.length; j++)
      {
        var smimeRecipient = self.smimeProcessedRecipients[j];
        if(pgpRecipient.email === smimeRecipient.email)
        {
          //merge entries to one
          var mergedRecipient = new RecipientKeyInfo(
            pgpRecipient.email,
            pgpRecipient.isPGPChecked,
            pgpRecipient.isPGPAvailable,
            pgpRecipient.isPGPVVV,
            smimeRecipient.isSMIMEChecked,
            smimeRecipient.isSMIMEAvailable,
            smimeRecipient.isSMIMEVVV,
            null,
            null
          );

          if(self.isRecipientProcessed(mergedRecipient.email) === false)
          {
            self.processedRecipients.push(mergedRecipient);
            self.deleteRecipientToProcess(mergedRecipient.email);
            self.recipientsInQueue--;

          }

          self.deletePgpRecipientToProcess(mergedRecipient.email);
          self.deleteSmimeRecipientToProcess(mergedRecipient.email);
        }
      }
    }
  },
  onRecipientProcessed: function() {
    Application.console.log("onRecipientProcessed called");
    this.callback(this.recipientsToProcess, this.processedRecipients);
  },
  onPgpRecipientProcessed: function() {
    Application.console.log("onPgpRecipientProcessed called");
    this.mergeProcessedRecipients();
    this.onRecipientProcessed();
  },
  onSmimeRecipientProcessed: function() {
    Application.console.log("onSmimeRecipientProcessed called");
    this.mergeProcessedRecipients();
    this.onRecipientProcessed();
    this.callback(this.recipientsToProcess, this.processedRecipients);
  },
  updateCache: function(callback) {
    //TODO: implement
  },
  updateCacheIfNeeded: function(callback) {
    //TODO: needed?
  },
  _cacheKey2KeyInfo: function(cacheKey) {
    var processedRecipient = {};
    if(cacheKey.source === "vvv-server")
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, true, true, true, false, false, false, "", null);
    }
    else if(cacheKey.source === "local")
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, true, true, false, false, false, false, "", null);
    }
    else
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, true, false, false, false, false, false, "", null);
    }
    return processedRecipient;
  },
  _cacheCert2KeyInfo: function(cacheKey) {
    var processedRecipient = {};
    if(cacheKey.source === "vvv-server")
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, false, false, false, true, true, true, "", null);
    }
    else if(cacheKey.source === "local")
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, false, false, false, true, true, false, "", null);
    }
    else
    {
      processedRecipient = new RecipientKeyInfo(cacheKey.email, false, false, false, true, false, false, "", null);
    }
    return processedRecipient;
  },
  _localKey2KeyInfo: function(email) {
    if(KeyManager.isPubKeyAvailable(email)) {
      //TODO: add SMIME check
      //TODO: load local key with KeyManager
      var localPGPKeys = KeyManager.getPublicKeys(email);

      if(localPGPKeys.length > 0)
      {
        processedRecipient = new RecipientKeyInfo(email, true, true, false, false, false, false, localPGPKeys[0], null);
      }
      else
      {
        processedRecipient = new RecipientKeyInfo(email, false, false, false, false, false, false, null, null);
      }
    }
    else
    {
      processedRecipient = new RecipientKeyInfo(email, false, false, false, false, false, false, null, null);
    }
    return processedRecipient;
  },
  _cleanAfterSearch: function(email, processedRecipient) {
    //TODO: try to merge queues
    var self = this;
    Application.console.log("Clean after search");
    if(self.isRecipientProcessed(email) === false) {
      self.processedRecipients.push(processedRecipient);
      self.deleteRecipientToProcess(email);
      self.pgpRecipientsInQueue--;
      self.onRecipientProcessed();
    }
  },
  _cleanAfterSearchSMIME: function(email, processedRecipient) {
    var self = this;
    Application.console.log("SMIME: Clean after search");
    if(self.isSmimeRecipientProcessed(email) === false) {
      self.smimeProcessedRecipients.push(processedRecipient);
      self.deleteSmimeRecipientToProcess(email);
      self.smimeRecipientsInQueue--;
      self.onSmimeRecipientProcessed();
    }
  },
  _cleanAfterSearchPGP: function(email, processedRecipient) {
    var self = this;
    Application.console.log("PGP: Clean after search");
    if(self.isPgpRecipientProcessed(email) === false) {
      self.pgpProcessedRecipients.push(processedRecipient);
      self.deletePgpRecipientToProcess(email);
      self.pgpRecipientsInQueue--;
      self.onPgpRecipientProcessed();
    }
  },
  updateKeys: function(callback) {
    var self = this;
    var cacheEntries = vvvKeyCache.getAllKeys();
    if(cacheEntries === null)
    {
      return;
    }
    var recipientsArray = [];
    for(var i = 0; i < cacheEntries.length; i++) {
      recipientsArray.push(cacheEntries[i].email);
    }
    self.addRecipients(recipientsArray, function() {});
    callback();
  }
};


/**
 *  Module containing functions to interact with thunderbird accounts
 * @module AccountManager
 */
var AccountManager = {
  /**
   * Get thunderbird accounts
   * @function
   * @memberof module:AccountManager
   * @return {Array} Array containing email-addresses
   */
  getAccounts: function () {
    Logger.debug("AccountManager.getAccounts");
    var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                            .getService(Components.interfaces.nsIMsgAccountManager);
    var accounts = accMgr.accounts;
    if (accounts.queryElementAt) {
      // Gecko 17+
      for (var i = 0; i < accounts.length; i++) {
        var account = accounts.queryElementAt(i, Components.interfaces.nsIMsgAccount);
        // Get identities from account
        var emailAddresses = [];
        for (var j= 0; j < account.identities.length; j++) {
          var identity = account.identities.queryElementAt(j, Components.interfaces.nsIMsgIdentity);
          emailAddresses.push(identity.email);
        }
        return emailAddresses;
      }
    }
    return [];
  }
};

/* Globally accessible OpenPGP.Keyring instance */
//var openpgp = window.openpgp;
var Keyring;
if(typeof window === "undefined") {
  Keyring = new openpgp.Keyring();
}
else {
  Keyring = new window.openpgp.Keyring();
}


/**
 *  Module containing functions to interact with keys
 * @module KeyManager
 */
var KeyManager = {
  init: function () {
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var Application = Cc["@mozilla.org/steel/application;1"]
                    .getService(Ci.steelIApplication);
    this.getAllPublicKeys();
    //TODO: callback?
  },
  keyring: {},
  /**
   * Imports all public keys from GnuPG to the OpenPGP.js keyring
   * @function
   * @memberof module:KeyManager
   */
  getAllPublicKeys: function () {
    Logger.debug("KeyManager.getAllPublicKeys");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    GPGIPC.getPubRingArmored(function (gpgKeys) {
      Logger.trace("KeyManager.getAllPublicKeys: getPubRingArmored finished");
      //important
      var keys = gpgKeys;
      Keyring.publicKeys.importKey(keys);
      Logger.trace("KeyManager.getAllPublicKeys: Armored keys: " + keys);
      //Logger.trace("KeyManager.getAllPublicKeys: Unarmored keys: " + window.openpgp.key.readArmored(gpgKeys));
      return;
    });
  },
  /**
   * Checks if a public pgp key is available for an email address
   * @function
   * @memberof module:KeyManager
   * @param {string} email
   * @return {bool} true, if public pgp key is available for mail address
   */
  isPubKeyAvailable: function (email) {
    Logger.debug("KeyManager.isPubKeyAvailable");
    this.getAllPublicKeys();
    var keys = Keyring.publicKeys.getForAddress(email);
    if(keys.length === 0) {
      return false;
    }
    return true;
  },
  /**
   * Checks if a public certificate is available for an email address
   * @function
   * @memberof module:KeyManager
   * @param {string} email
   * @return {bool} true, if public cert is available for mail address
   */
  isCertAvailable: function (email) {
    if (email == null) {
  		return false;
  	}

  	var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
  					.getService(Components.interfaces.nsIMsgAccountManager);
  	var accounts = accMgr.accounts;

  	for (var i=0; i<accounts.length; i++) {
  		var account = accounts.queryElementAt(i, Components.interfaces.nsIMsgAccount);
  		for (var j= 0; j < account.identities.length; j++) {
  			var identity = account.identities.queryElementAt(j, Components.interfaces.nsIMsgIdentity);
  			if (identity.email == email) {
  				var certname = identity.getUnicharAttribute("encryption_cert_name");

  				var certdb = Components.classes[nsX509CertDBContractID].getService(nsIX509CertDB);
  				if (!certdb) {
  					Application.console.log("certdb is null");
  					return false;
  				}
  				var cert = certdb.findEmailEncryptionCert(certname);
          if(cert === null) {
            return false;
          }
          return true;
  			}
  		}
  	}
  	return false;
  },

  getPublicKeys: function (email) {
	  Logger.debug("KeyManager.getPublicKey");
	  this.getAllPublicKeys();
	  var keys = Keyring.publicKeys.getForAddress(email);

	  return keys;
  },

  /**
   * Checks if public pgp keys are available for multiple mail addresses
   * @function
   * @memberof module:KeyManager
   * @param {Array} Array of email addresses
   * @return {Array} Array of email addresses for which keys are available
   */
  checkAddressesForKeys: function (emails) {
    Logger.debug("KeyManager.checkAddressesForKeys");
    //TODO:
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var emailsWithKey = [];
    for(var i=0; i<emails.length; i++) {
      if(this.isPubKeyAvailable(emails[i]))
      {
        emailsWithKey.push(emails[i]);
      }
    }
    return emailsWithKey;
  },
  /**
   * Collects all keys and accounts and returns an object with AccountKeyInfos
   * @function
   * @memberof module:KeyManager
   * @return {object} Object which contains an Array of AccountKeyInfo in "object.accounts"
   */
  getAccountKeyInfos: function () {
    Logger.debug("KeyManager.getAccountKeyInfos");
    var mailAccounts = AccountManager.getAccounts();
    var accountsWithPGPKeys = KeyManager.checkAddressesForKeys(mailAccounts);

    var accountKeyInfos = [];
    for (var i= 0; i < accountsWithPGPKeys.length; i++) {
      var pgpKeys = Keyring.publicKeys.getForAddress(accountsWithPGPKeys[i]);
      if(pgpKeys.length === 0) {
        //TODO: return error / exception
      }
      //TODO: check VVV status
      var keyInfoPGP = new KeyInfo(pgpKeys[0].getExpirationTime(), pgpKeys[0].primaryKey.getKeyId().toHex(), pgpKeys[0].primaryKey.getFingerprint(), false);
      var keyInfoSMIME = null;////TODO: new KeyInfo("", key_id, fingerprint, vvvregistered);
      var accountKeyInfo = new AccountKeyInfo(accountsWithPGPKeys[i], true, keyInfoPGP, false, keyInfoSMIME);
      accountKeyInfos.push(accountKeyInfo);

    }
    var returnObject = {
      accounts: accountKeyInfos
    };
    return returnObject;
  },
  publishKey: function () {
    Logger.debug("KeyManager.publishKey");
    //TODO:
    //get SRV Record
    //send publish request
  },
  importKeyFromHKP: function () {
      //TODO:
  }
};

var CertDBManager = {
  getCert: function(email) {
    let certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);

    let enumerator = certdb.getCerts().getEnumerator();
    while (enumerator.hasMoreElements()) {
      let cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);

      if(cert.emailAddress == email)
      {
        Application.console.log("Found local cert for: " + email);
        var length = {};
        var derArray = cert.getRawDER(length);
        var certArray = new Uint8Array(derArray);

        return certArray;
      }
    }
    Application.console.log("Found **no**  local cert for: " + email);
    return null;
  },
  /** Adds a certificate in PEM (base64) form to Thunderbird's cert store */
  addCert: function (der_cert) {
    // See: https://mike.kaply.com/2015/02/10/installing-certificates-into-firefox/
    let certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    //TODO: delete
    /*
    let beginCert = "-----BEGIN CERTIFICATE-----";
    let endCert = "-----END CERTIFICATE-----";
    base64cert = base64cert.replace(/[\r\n]/g, "");
    let begin = base64cert.indexOf(beginCert);
    let end = base64cert.indexOf(endCert);
    let cert = base64cert.substring(begin + beginCert.length, end)
    */
    //let cert = certdb.constructX509(der_cert, der.length);
    var CERT_TRUST = ",CPu,";
    certdb.addCert(atob(der_cert), CERT_TRUST, "");
  },
  /**
   * Checks if a public certificate is available for an email address
   * @function
   * @memberof module:CertDBManager
   * @param {string} email
   * @return {bool} true, if public cert is available for mail address
   */
  isCertAvailable: function (email) {
    if (email == null) {
  		return false;
  	}

    /*
		//var certdb = Components.classes[nsX509CertDBContractID].getService(nsIX509CertDB);
    let certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    var nsIX509Cert = Components.interfaces.nsIX509Cert;
		if (!certdb) {
			Application.console.log("certdb is null");
			return false;
		}
    var cert;
    try {
      Application.console.log("Trying to fetch local cert: " + email);
      cert = certdb.findCertByEmailAddress(email);
    } catch (e) {
      Application.console.log("Exception: " + e.message);
    }

    if(cert === null) {
      return false;
    }
    return true;
    */
    let certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    //let certcache = Components.classes["@mozilla.org/security/nsscertcache;1"].createInstance(Ci.nsINSSCertCache);
    //certcache.cacheAllCerts();
    //let enumerator = certcache.getX509CachedCerts().getEnumerator();
    let enumerator = certdb.getCerts().getEnumerator();
    while (enumerator.hasMoreElements()) {
      let cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
      /*
      let sslTrust = certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
                                          Ci.nsIX509CertDB.TRUSTED_SSL);
      let emailTrust = certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
                                            Ci.nsIX509CertDB.TRUSTED_EMAIL);
      let objsignTrust = certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
        Ci.nsIX509CertDB.TRUSTED_OBJSIGN);
      */
      if(cert.emailAddress == email)
      {
        Application.console.log("Found local cert for: " + email);
        return true;
      }
    }
    Application.console.log("Found **no**  local cert for: " + email);
    return false;
  }

};


var LDAPTool = {
  updateCert: function (keyServer, email, user, password, certPath, callback) {
    //TODO: use keyserver arg
    var subProcStdOut = "";
    var subProcCommand = "";
    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/ldap_tool.exe");
    } else {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/ldap_tool");
    }
    Application.console.log("ldap-update-path: " + subProcCommand);
    Application.console.log("ldap-update-email: " + email);

    //create & use user_string for authentication
    var email_split = email.split("@");
    email_split = email_split[1].split(".");
    var tld = email_split[email_split.length];
    var baseName = email_split[email_split.length - 1];
    var userStr = "cn=" + user + ",dc=" + baseName + ",dc=" + tld;
    Application.console.log("user: " + userStr);

    var subProcArgs = ['-a', 'update_cert', '-e', email, '-u', userStr, '-p', password, '-c', certPath];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        callback(subProcStdOut);
      }
    };
    subprocess.call(subProcOptions).wait();
  },


  deleteCert: function (keyServer, email, user, password, callback) {
    //TODO: use keyserver arg
    var subProcStdOut = "";
    var subProcCommand = "";
    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/ldap_tool.exe");
    } else {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/ldap_tool");
    }
    Application.console.log("ldap-update-path: " + subProcCommand);
    Application.console.log("ldap-update-email: " + email);

    // create & use user_string for authentication
    var email_split = email.split("@");
    email_split = email_split[1].split(".");
    var tld = email_split[email_split.length];
    var baseName = email_split[email_split.length - 1];
    var userStr = "cn=" + user + ",dc=" + baseName + ",dc=" + tld;
    Application.console.log("user: " + userStr);

    var subProcArgs = ['-a', 'delete_cert', '-e', email, '-u', userStr, '-p', password];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        callback(subProcStdOut);
      }
    };
    subprocess.call(subProcOptions).wait();
  },



  lookup: function(keyServer, email, callback) {
    Application.console.log("ldap-server: " + keyServer);
    LDAPTool.getServerCert(keyServer, function(isCertFound){

      Application.console.log("LDAPTool.lookup: Server cert found: " + keyServer + ", " + email);
      //TODO: use keyserver arg
      var subProcStdOut = "";
      var subProcCommand = "";
      var certPath = "";
      if(CommonUtils.getOS() == "WINNT") {
        subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/ldap_tool.exe");
        certPath = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/certs/" + keyServer);
      } else {
        subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/ldap_tool");
        certPath = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/certs/" + keyServer);
      }
      Application.console.log("ldap-lookup-path: " + subProcCommand);
      Application.console.log("ldap-lookup-email: " + email);
      var subProcArgs = ['-a', 'get_cert', '-e', email, '-c', certPath];
      var subProcOptions = {
        command: subProcCommand,
        arguments: subProcArgs,
        stdout: function(data) {
          subProcStdOut += data;
        },
        done: function(result) {
          Application.console.log("LDAPTool.lookup result: " + subProcStdOut);
          callback(subProcStdOut);
        }
      };
      subprocess.call(subProcOptions);
    });
  },
  /**
   * Returns the LDAP-server address for a domain, if there is an entry at the DNS-server of the provider.
   * @function
   * @memberof module:LDAPTool
   * @param {string} mailDomain - The domain of the mail provider
   * @param {function} callback - Callback function which receives the LDAP-server address as string.
   */
  getVVVLDAP: function(mailDomain, callback) {
    Logger.debug("LDAPTool.getVVVLDAP");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var subProcStdOut = "";
    var subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/SecureFetch");
    var workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('/'));

    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/SecureFetch.exe");
      workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('\\'));
    }

    Application.console.log("getVVVLDAP-FilePath: " + subProcCommand);
    Application.console.log("getVVVLDAP-domain: " + mailDomain);
    Application.console.log("getVVVLDAP-work-dir: " + workDir);

    var subProcArgs = ['-smime', mailDomain];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      workdir: workDir,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        Application.console.log("getVVVLDAP-Result: " + JSON.stringify(result));
        var parsedResult = subProcStdOut;

        if(parsedResult.indexOf('.') != -1)
        {
          subProcStdOut = subProcStdOut.slice(0, -1);
          callback(subProcStdOut);
        }
        else
        {
          callback("");
        }
      }
    };
    subprocess.call(subProcOptions).wait();
  },
  // Fetchs, verifies and saves the LDAP server certificate
  getServerCert: function(ldapDomain, callback) {
    Logger.debug("LDAPTool.getServerCert");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var subProcStdOut = "";
    var subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/gnu/SecureFetch");
    var workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('/'));

    if(CommonUtils.getOS() == "WINNT") {
      subProcCommand = CommonUtils.chrome2FilePath("chrome://vvv-addon/content/native/win/SecureFetch.exe");
      workDir = subProcCommand.substring(0, subProcCommand.lastIndexOf('\\'));
    }

    Application.console.log("getServerCert-FilePath: " + subProcCommand);
    Application.console.log("getServerCert-domain: " + ldapDomain);
    Application.console.log("getServerCert-work-dir: " + workDir);

    var subProcArgs = ['-ldap-cert', ldapDomain];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      workdir: workDir,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        Application.console.log("getVVVLDAP-Result: " + JSON.stringify(result));
        var parsedResult = subProcStdOut;

        if(parsedResult.indexOf('true') != -1)
        {
          callback(false);
        }
        callback(true);
      }
    };
    subprocess.call(subProcOptions);
  }
};


/**
 *  Module containing functions for IPC with GnuPG
 * @module GPGIPC
 */
var GPGIPC = {
  /**
   * Fetchs the Public Keyring from GnuPG as armored string
   * @function
   * @memberof module:GPGIPC
   * @param {function} callback callback function which is called with the public keyring
   * @return {string} Armored public keyring as string
   */
  getPubRingArmored: function(callback) {
    Logger.debug("GPGIPC.getPubRingArmored");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    Cu.import("chrome://vvv-addon/content/ui/js/subprocess.jsm");

    CommonUtils.getGPGPath(function (gpgPath) {
      var subProcStdOut = "";
      var subProcCommand = gpgPath;
      var subProcArgs = ['--export', '--armor'];
      var subProcOptions = {
        command: subProcCommand,
        arguments: subProcArgs,
        stdout: function(data) {
          subProcStdOut += data;
        },
        done: function(result) {
          callback(subProcStdOut);
        }
      };
      subprocess.call(subProcOptions).wait();
    });
  },
  _gpgExportArmored: function (gpgPath, callback) {
    //TODO: ...
  },
  /**
   * Imports an armored public pgp-key to GnuPG
   * @function
   * @memberof module:GPGIPC
   * @param {string} sKey - Armored public pgp-key to import
   * @param {function} callback callback function, which is called after the import finished
   */
  importKey: function (sKey, callback) {
    Logger.debug("GPGIPC.importKey");
    //TODO: create temporary file and copy gpgKey to it
    Components.utils.import("resource://gre/modules/osfile.jsm");
    //TODO:
    //get path for temporary file
    var filePath = OS.Path.join(OS.Constants.Path.profileDir, "tmp_gpg_key.txt");
    var tmpFile = OS.Path.join(OS.Constants.Path.profileDir, "tmp_buffer.txt");

    var encoder = new TextEncoder();
    var txtArray = encoder.encode(sKey);
    var promise = OS.File.writeAtomic(filePath, txtArray, {tmpPath: tmpFile});

    //TODO: try-catch
    promise.then(
      function() {
        CommonUtils.getGPGPath(function (gpgPath) {
          var subProcStdOut = "";
          var subProcCommand = gpgPath;
          var subProcArgs = ['--import', filePath];
          var subProcOptions = {
            command: subProcCommand,
            arguments: subProcArgs,
            stdout: function(data) {
              subProcStdOut += data;
            },
            done: function(result) {
              Logger.trace("GPGIPC.importKey: GPG returned: " + subProcStdOut);
              var removeFilePromise = OS.File.remove(filePath, {ignoreAbsent: true});
              removeFilePromise.then(function () {
                Logger.trace("GPGIPC.importKey: remove temp file was successful");
                callback(subProcStdOut);
              },
              function() {
                Logger.warn("GPGIPC.importKey: remove temp file failed");
                //TODO:
              }
            );

            }
          };
          subprocess.call(subProcOptions).wait();
        });
      },
      function(aRejectReason) {
        //TODO: throw exception
        Logger.warn("GPGIPC.importKey: creation of temp file failed with the following reason: " + aRejectReason);
      }
    );
  },
  /**
   * Deletes an armored public pgp-key from GnuPG keystore
   * @function
   * @memberof module:GPGIPC
   * @param {string} keyIdentifier - KeyIdentifier of the key e.g. "Hans Mustermann <hans.mustermann@mustermann.de>"
   * @param {function} callback callback function, which is called after the deletion
   */
  deleteKey: function (keyIdentifier, callback) {
    Logger.debug("GPGIPC.deleteKey");
    CommonUtils.getGPGPath(function (gpgPath) {
      var subProcStdOut = "";
      var subProcCommand = gpgPath;
      var subProcArgs = ['--batch', '--yes', '--delete-key', keyIdentifier];
      var subProcOptions = {
        command: subProcCommand,
        arguments: subProcArgs,
        stdout: function(data) {
          subProcStdOut += data;
        },
        done: function(result) {
          callback(subProcStdOut);
        }
      };
      subprocess.call(subProcOptions).wait();
    });
  },
  getSecRingArmored: function (callback) {

  }
};

/**
 *  Module containing helper functions and utilities
 * @module CommonUtils
 */
var CommonUtils = {
  /**
   * Returns the OS as string, e.g. "WINNT" for "Windows", complete list at https://developer.mozilla.org/en-US/docs/Mozilla/Developer_guide/Build_Instructions/OS_TARGET
   * @function
   * @memberof module:CommonUtils
   * @return {string} OS as string
   */
  getOS: function () {
    Logger.debug("CommonUtils.getOS");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var xulRuntime = Cc["@mozilla.org/xre/app-info;1"].getService(Ci.nsIXULRuntime);
    return xulRuntime.OS;
  },
  //TODO: delete ?
  checkPassword: function (email, password) {
    Application.console.log("CommonUtils.checkPassword");
    var accMgr = Components.classes["@mozilla.org/messenger/account-manager;1"]
                            .getService(Components.interfaces.nsIMsgAccountManager);
    var accounts = accMgr.accounts;
    Application.console.log("checkPassword: got accounts");
    if (accounts.queryElementAt) {
      // Gecko 17+
      for (var i = 0; i < accounts.length; i++) {
        var account = accounts.queryElementAt(i, Components.interfaces.nsIMsgAccount);
        Application.console.log("checkPassword: got specific account");
        // Get identities from account
        for (var j= 0; j < account.identities.length; j++) {
          var identity = account.identities.queryElementAt(j, Components.interfaces.nsIMsgIdentity);
          Application.console.log("checkPassword: got identities");
          //emailAddresses.push(identity.email);
          Application.console.log("idEmail: " + identity.email + ", input-email: " + email);
          if(identity.email === email) {
            Application.console.log("checkPassword: found identity for email-address");
            //source: https://dxr.mozilla.org/comm-central/source/mail/components/accountcreation/content/verifyConfig.js#60
            //var server = identity.incomingServer;
            var server = account.incomingServer;

            //source: line 134: https://searchcode.com/codesearch/view/21376879/
            Application.console.log("hostname: " + account.incomingServer.hostName);
            let count = {};
            let loginMgr = Cc["@mozilla.org/login-manager;1"].getService(Ci.nsILoginManager);
            let logins = loginMgr.findLogins(count, "imap://" + account.incomingServer.hostName, null,
                                   "imap://" + account.incomingServer.hostName);
            var serverPassword = logins[0].password;
            //TODO: delete!
            Application.console.log("Server Password: " + serverPassword);
            if(serverPassword === "") {
              //TODO: check password against server
            }
            if(serverPassword === password)
            {
              return true;
            }
          }
        }
      }
      return false;
    }
    var logins = Services.logins.findLogins({}, url, null, url);

  },
  /**
   * Returns the path for the GnuPG executable
   * @function
   * @memberof module:CommonUtils
   * @return {string} GnuPG path as string
   */
  getGPGPath: function (callback) {
    Logger.debug("CommonUtils.getGPGPath");
    //TODO: check for different linux paths
    var gpgPath = '/usr/bin/gpg2';
    if(CommonUtils.getOS() == "WINNT")
    {
      CommonUtils.getWinGpgPath(function(returnedPath) {
        callback(returnedPath);
      });
    }
    else {
      callback(gpgPath);
    }
  },
  /**
   * Returns the path of the GnuPG executable on windows machines
   * @function
   * @memberof module:CommonUtils
   * @param {function} callback callback function which is called with the returned string
   * @return {string} path to GnuPG executable
   */
  getWinGpgPath: function (callback) {
    //TODO: should be private
    Logger.debug("CommonUtils.getWinGPGPath");
    var { classes: Cc, interfaces: Ci, utils: Cu } = Components;
    var Application = Cc["@mozilla.org/steel/application;1"]
                    .getService(Ci.steelIApplication);
    var subProcStdOut = "";
    Application.console.log("Z356: Entered getWinGpgPath");
    var subProcCommand = this.chrome2FilePath("chrome://vvv-addon/content/native/win/WinGetEnv.exe");
    Application.console.log("FilePath: " + subProcCommand);
    var subProcArgs = [];
    var subProcOptions = {
      command: subProcCommand,
      arguments: subProcArgs,
      stdout: function(data) {
        subProcStdOut += data;
      },
      done: function(result) {
        //TODO: delete ...
        Application.console.log("StdOut: " + subProcStdOut);
        subProcStdOut = subProcStdOut.toLowerCase();
        var PATHArray = subProcStdOut.split(";");

        for(var i = 0; i < PATHArray.length; i++) {
          if(PATHArray[i].indexOf("gnupg") !== -1) {
            //Application.console.log("GPG Path: " + PATHArray[i]);
            var gpgPath = PATHArray[i] + "\\gpg.exe";
            Application.console.log("Callback: " + gpgPath);
            callback(gpgPath);
          }
        }
        //TODO: no GPG found
        //callback("Z672: No GPGPath");
      }
    };
    subprocess.call(subProcOptions).wait();
  },
  /**
   * Returns a file path for a given chrome path e.g. chrome://vvv-addon/content/native/WinGetEnv.exe
   * @function
   * @memberof module:CommonUtils
   * @param {string} chromePath chrome path to the file
   * @return {string} file path for the given chrome path
   */
  chrome2FilePath: function (chromePath) {
    Logger.debug("CommonUtils.chrome2FilePath");
    Components.utils.import("resource://gre/modules/Services.jsm");
    var cr = Components.classes['@mozilla.org/chrome/chrome-registry;1'].getService(Components.interfaces.nsIChromeRegistry);
    var chromeURI = Services.io.newURI(chromePath, 'UTF-8', null);
    var localFile = cr.convertChromeURL(chromeURI); //TODO: delete example comments
    var filePath = localFile.path; // "file:///C:/Users/Vayeate/AppData/Roaming/Mozilla/Firefox/Profiles/aecgxse.Unnamed%20Profile%201/extensions/youraddon@jetpack.xpi!/mySubFolder/myCFunctionsForUnix.so"
    var returnPath = filePath;//TODO: //filePath.substring(8);
    if(CommonUtils.getOS() !== "WINNT") {
      return returnPath;
    }
    if(returnPath[0] === '/')
    {
      returnPath = filePath.substring(1);
      returnPath = returnPath.replace(/\//g, "\\");
    }
    return returnPath;
  },
  hexToByte: function(str) {
    //TODO:
    /*
    if (!str) {
      return new Uint8Array();
    }
*/
    var a = [];
    for (var i = 0, len = str.length; i < len; i+=2) {
      a.push(parseInt(str.substr(i,2),16));
    }

    return new Uint8Array(a);
  },
  byteArrayToB64: function(byteArray) {
    return btoa(String.fromCharCode.apply(null, byteArray));
  },
  hexToBase64: function(hexstring) {
    var b64 = btoa(String.fromCharCode.apply(null,
                hexstring.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
              );
    Application.console.log("Base64: " + b64);
    return b64;
  }
};
