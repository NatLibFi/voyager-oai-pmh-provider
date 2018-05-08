# Voyager OAI-PMH Provider

A fully-featured OAI-PMH Provider (server) implementation for Voyager ILS with customizable set definitions.

### Features

* Support for all verbs (functions) of OAI-PMH 2.0
* Configurable sets
* Support for keyword indexes
* Return records in Dublin Core as well as MARCXML
* Access control for IP addresses
* Support for handling of deletions
* Return bib and/or authority records
* Support for record linking (component parts -> host records)
* Support for embedding holdings information in bib records

## Installation

1. Copy oai-pmh.cgi to directory /m1/voyager/xxxdb/webvoyage/cgi-bin (or wherever your cgi-bin resides)
2. Set it executable (chmod +x oai-pmh.cgi). As a result, the directory listing using command ls -l should show something like the following:

        -rwxrwxr-x 1 voyager linda 20431 Oct 17 14:32 oai-pmh.cgi

3. Verify that Perl path is correct on the first line of oai-pmh.cgi. On our server the correct Perl installation is under Oracle, but on a typical Voyager installation the correct first line is:

        #!/m1/shared/bin/perl

4. Copy oai-pmh.config to the same directory

5. Open oai-pmh.config with a text editor and change the settings in the beginning of the file. The most important settings to get going are the database settings. If the WebVoyáge server is the database server, it's usually enough to set the user id and password. If not, also the address of the database server is needed. Make sure that Oracle really is installed in the path provided in ORACLE_HOME setting and modify if necessary. Keyword server address and port need to be set only if keyword rules are used in set specifications.

6. Test that the script works correctly by entering URL:

        http://server/cgi-bin/oai-pmh.cgi?verb=Identify using a web browser.

You can have multiple oai-pmh scripts in cgi-bin with their own settings. Just copy both the script and the config file to similar names (e.g. oai-pmh-custom.cgi and oai-pmh-custom.config). The custom-named script will read the custom config file automatically, so there's no need to modify the script file.

## License and copyright

Copyright (c) 2005-2018 University Of Helsinki (The National Library Of Finland)

This project's source code is licensed under the terms of **GNU Affero General Public License Version 3**.
