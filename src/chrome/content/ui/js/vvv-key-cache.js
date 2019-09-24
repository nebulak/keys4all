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
const Cc = Components.classes;
const Ci = Components.interfaces;

Components.utils.import("resource://gre/modules/Sqlite.jsm");


//source: vvv-server, local, not-found
var vvvKeyCache = {
  m_dbName: "vvv-key-cache.sqlite",

  onLoad: function() {
    // initialization code
    this.initialized = true;
    this.init();
  },

  dbConnection: null,

  dbSchema: {
     tables: {
       pgp_keys: "email          TEXT NOT NULL, \
                  source         TEXT NOT NULL, \
                  last_update    TEXT NOT NULL, \
                  fingerprint    TEXT",
       smime_keys: "email          TEXT NOT NULL, \
                  source         TEXT NOT NULL, \
                  last_update    TEXT NOT NULL, \
                  fingerprint    TEXT"
                  /*,
       domains: "domain         TEXT NOT NULL, \
                 is_vvv         BOOL NOT NULL, \
                 last_update    TEXT NOT NULL"*/
    }
  },

  init: function() {
    var dirService = Cc["@mozilla.org/file/directory_service;1"].
      getService(Ci.nsIProperties);

    var dbFile = dirService.get("ProfD", Ci.nsIFile);
    dbFile.append(this.m_dbName);

    var dbService = Cc["@mozilla.org/storage/service;1"].
      getService(Ci.mozIStorageService);

    var dbConnection;

    if (!dbFile.exists())
      dbConnection = this._dbCreate(dbService, dbFile);
    else {
      dbConnection = dbService.openDatabase(dbFile);
    }
    this.dbConnection = dbConnection;
  },

  getKey: function(email) {
    //Application.console.log("dbConnection: " + this.dbConnection);
    try {
      Application.console.log("Creating statement ....");
      var statement = this.dbConnection.createStatement("SELECT email, source, last_update, fingerprint FROM pgp_keys WHERE email = :email");
      statement.params.email = email;
      var rows = [];
      Application.console.log("executing steps ...");
      while (statement.executeStep()) {
        var rowObject = {};
        rowObject.email = statement.row.email;
        rowObject.source = statement.row.source;
        rowObject.last_update = statement.row.last_update;
        rowObject.fingerprint = statement.row.fingerprint;

        Application.console.log("SQLite: Row.email: " + statement.row.email);
        Application.console.log("SQLite: Row.source: " + statement.row.source);
        Application.console.log("SQLite: Row.last_update: " + statement.row.last_update);
        rows.push(rowObject);
        //var row = statement.row.id;
      }
      statement.reset();
      Application.console.log("Got " + rows.length + " rows");
      //Application.console.log("Key-Cache: Found " + JSON.stringify(rows));
      if(rows.length === 0)
      {
        return null;
      }
      Application.console.log("Key-Cache: Found " + rows[0].email);
      return rows[0];
    } catch (e) {
      Application.console.log(e.message);
    }

  },

  saveKey: function(email, source, fingerprint) {
    //insert into table if email address does NOT exist
    if(this.getKey(email) == null) {

      var statement = this.dbConnection.createStatement('INSERT INTO pgp_keys (email, source, last_update, fingerprint) VALUES (:email, :source, :last_update, :fingerprint)');// + email + ', ' + source + ', ' + new Date().toString() + ')');
      statement.params.email = email;
      statement.params.source = source;
      statement.params.last_update = new Date().toString();
      statement.params.fingerprint = fingerprint;
      statement.execute();
      Application.console.log("Key-Cache: Created " + email);

    }
    //update table row if entry already does exist
    else {
      var statement = this.dbConnection.createStatement('UPDATE pgp_keys SET source = :source, last_update = :last_update, fingerprint = :fingerprint WHERE email = :email');// + source + ', last_update = ' + new Date().toString() + ' WHERE email = ' + email);
      statement.params.email = email;
      statement.params.source = source;
      statement.params.last_update = new Date().toString();
      statement.params.fingerprint = fingerprint;
      statement.execute();
      Application.console.log("Key-Cache: Updated " + email);

    }
  },
  getAllKeys: function() {
    try {
      Application.console.log("Creating statement ....");
      var statement = this.dbConnection.createStatement("SELECT email, source, last_update, fingerprint FROM pgp_keys");
      var rows = [];
      while (statement.executeStep()) {
        var rowObject = {};
        rowObject.email = statement.row.email;
        rowObject.source = statement.row.source;
        rowObject.last_update = statement.row.last_update;
        rowObject.fingerprint = statement.row.fingerprint;

        rows.push(rowObject);
        //var row = statement.row.id;
      }
      statement.reset();
      Application.console.log("Got " + rows.length + " rows");
      //Application.console.log("Key-Cache: Found " + JSON.stringify(rows));
      if(rows.length === 0)
      {
        return null;
      }
      return rows;
    } catch (e) {
      Application.console.log(e.message);
    }
  },

    getCert: function(email) {
      //Application.console.log("dbConnection: " + this.dbConnection);
      try {
        Application.console.log("Creating statement ....");
        var statement = this.dbConnection.createStatement("SELECT email, source, last_update, fingerprint FROM smime_keys WHERE email = :email");
        statement.params.email = email;
        var rows = [];
        Application.console.log("executing steps ...");
        while (statement.executeStep()) {
          var rowObject = {};
          rowObject.email = statement.row.email;
          rowObject.source = statement.row.source;
          rowObject.last_update = statement.row.last_update;
          rowObject.fingerprint = statement.row.fingerprint;

          Application.console.log("SQLite: Row.email: " + statement.row.email);
          Application.console.log("SQLite: Row.source: " + statement.row.source);
          Application.console.log("SQLite: Row.last_update: " + statement.row.last_update);
          rows.push(rowObject);
          //var row = statement.row.id;
        }
        statement.reset();
        Application.console.log("Got " + rows.length + " rows");
        //Application.console.log("Key-Cache: Found " + JSON.stringify(rows));
        if(rows.length === 0)
        {
          return null;
        }
        Application.console.log("Key-Cache: Found " + rows[0].email);
        return rows[0];
      } catch (e) {
        Application.console.log(e.message);
      }

    },

    saveCert: function(email, source, fingerprint) {
      //insert into table if email address does NOT exist
      if(this.getCert(email) == null) {

        var statement = this.dbConnection.createStatement('INSERT INTO smime_keys (email, source, last_update, fingerprint) VALUES (:email, :source, :last_update, :fingerprint)');// + email + ', ' + source + ', ' + new Date().toString() + ')');
        statement.params.email = email;
        statement.params.source = source;
        statement.params.last_update = new Date().toString();
        statement.params.fingerprint = fingerprint;
        statement.execute();
        Application.console.log("Key-Cache: Created " + email);

      }
      //update table row if entry already does exist
      else {
        var statement = this.dbConnection.createStatement('UPDATE smime_keys SET source = :source, last_update = :last_update, fingerprint = :fingerprint WHERE email = :email');// + source + ', last_update = ' + new Date().toString() + ' WHERE email = ' + email);
        statement.params.email = email;
        statement.params.source = source;
        statement.params.last_update = new Date().toString();
        statement.params.fingerprint = fingerprint;
        statement.execute();
        Application.console.log("Key-Cache: Updated " + email);

      }
    },
    getAllCerts: function() {
      try {
        Application.console.log("Creating statement ....");
        var statement = this.dbConnection.createStatement("SELECT email, source, last_update, fingerprint FROM smime_keys");
        var rows = [];
        while (statement.executeStep()) {
          var rowObject = {};
          rowObject.email = statement.row.email;
          rowObject.source = statement.row.source;
          rowObject.last_update = statement.row.last_update;
          rowObject.fingerprint = statement.row.fingerprint;

          rows.push(rowObject);
          //var row = statement.row.id;
        }
        statement.reset();
        Application.console.log("Got " + rows.length + " rows");
        //Application.console.log("Key-Cache: Found " + JSON.stringify(rows));
        if(rows.length === 0)
        {
          return null;
        }
        return rows;
      } catch (e) {
        Application.console.log(e.message);
      }
  },
  isUpdateNeeded: function(updateTime, entry) {
    var dateNow = new Date();
    var lastUpdateDate = new Date(entry.last_update);
    var timeSinceUpdate = (dateNow.getTime() - lastUpdateDate.getTime())/1000;
    if( timeSinceUpdate < this.updateTime )
    {
      return false;
    }
    return true;
  },

  _dbCreate: function(aDBService, aDBFile) {
    var dbConnection = aDBService.openDatabase(aDBFile);
    this._dbCreateTables(dbConnection);
    return dbConnection;
  },

  _dbCreateTables: function(aDBConnection) {
    for(var name in this.dbSchema.tables)
      aDBConnection.createTable(name, this.dbSchema.tables[name]);
  },
};

if ('undefined' !== typeof window) {
  window.addEventListener("load", function(e) { vvvKeyCache.onLoad(e); }, false);
}else {
  vvvKeyCache.onLoad();
}
