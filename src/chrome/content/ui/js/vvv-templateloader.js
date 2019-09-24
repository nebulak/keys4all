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



/**
 * Class LoadTemplate loads the specified template file. After loading,
 * particular templates could be retrieven via the getTemplate method.
 * Synchronisation is done via the given deferred instance.
 */

LoadTemplate = function(deferred, filename, data) {
	this.filename = filename;
	this.data = data || null;

	var fileContent = "";

	// method that returns a string containing content of the file loaded.
    this.getAllTemplates = function() {
        return fileContent;
    }

    var jqxhr = $.get(this.filename, function(data) {
    	//console.log("Successfully loaded file " + this.filename);
         fileContent = data;
         deferred.resolve();
    },"html")
    .fail(function() {
    	var message = "Error: Failed loading the file containing all templates.\nPlease inform your administrator."
        console.log(message);
        deferred.reject(message);
    })

    // wait until the template has been loaded and member variable fileContent has been set.
    $.when(deferred).done(function(){
    	// do nothing
    })
}

LoadTemplate.prototype.getTemplate = function(templateId) {
	var template = $(this.getAllTemplates()).filter(templateId).html();

	// if template id is not found, we log the error and return undefined.
	if (!template) {
		console.log('Could not find template id "' + templateId + '" in file "' +  this.filename + '"');
	}
	return template;
}
