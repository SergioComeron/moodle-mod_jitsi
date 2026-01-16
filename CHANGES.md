# Changelog
## v4.2.0 (2025012700)
# Fixed
 * Mobile app error
 * Cache error
# Added
 * Add channellast configuration
 * **GCP Auto-Managed Servers**: Create Jitsi servers in Google Cloud Platform with one click
 * Automatic VM provisioning with Debian 12
 * JWT authentication automatically configured
 * Static IP address management (automatic reservation and reuse)
 * Let's Encrypt SSL certificate provisioning
 * Real-time server status monitoring (Running, Stopped, Provisioning, Error)
 * Start/Stop VM instances from Moodle interface to save costs
 * Detailed provisioning progress modal with status updates
 * DNS configuration helper with copy-to-clipboard functionality
 * Automatic cleanup of failed provisioning attempts
 * **Improved Server Management Interface**:
 * Separated views: table view for listing servers, dedicated form view for add/edit
 * "Add new server" button in table view
 * Cancel button in form view for better navigation
 * Clearer visual organization
# Changed
 * Removed "Deprecated" settings section (watermark link and simultaneous cameras)
 * Server management page now shows only relevant content based on action (list or form)
# Limitations
 * ⚠️ **Recording not yet supported** on GCP auto-managed servers
 * Recording and live streaming buttons are disabled on servers created via GCP
 * For recording functionality, use self-hosted servers (Type 1) or 8x8 servers (Type 2)
 * Recording support planned for future releases (v4.3+)

---

## v4.0 ()
# Fixed
 * Code style corrections
 * Some errors in the exception strings.
# Changed
 * Server management. Stores and manages multiple Jitsi servers.
 * Upgrade google api php to 2.18.4.
 * Config parameters migration. 
# Aded
 * Add Google api compute.
 
---

## v3.5 (20025041400)
# Fixed
 * Escape single quotes in the username before creating the session. #134
# Changed
 * Upgrade google api php to 2.18.3
 * data-toggle deprecation
 * deprecation custom-switch
 * deprecation text-right
# Added
 * Course overview integration

## v3.4.13 (2025028601)
# Fixed
  * tokeninvitacion empty when restore.

---

## v3.4.12 (2025021600)
# Fixed
  * Fixes problem with tokeninvitacion
  
  ---

## v3.4.11 (2024120100)
# Fixed
  * Fixes issue where recordings in shared sessions were not displayed in secondary sessions
# Changed
  * New version Google api 2.18.2
  ---

## v3.4.10 (2024111800)
# Changed
  * Now the attendance report has a button to view reports for a specific day
# Fixed
  * Final deprecation of MESSAGE_DEFAULT_LOGGEDOFF / MESSAGE_DEFAULT_LOGGEDIN
  * Fixed problem with timeopen and timeclose on shared sessions

---

## v3.4.9 (2024100900)
## Added
	*	A button is added to generate the list of participants and attended minutes.
	*	A page with graphs and statistics is added.

---

## v3.4.8 (2024092600)
## Fixed
  * Update mod_form.php to add completion rules with suffix based on branch version #128
## Added
  * Add experimental function to share stream with users outside the moodle. 
  * Cache for getminutes functions
## Changed
  * Replace tabs with buttons in view.
---

## v3.4.5 (2024081300)
## Fixed
  * Fix inplace editable recordname in view_table.php #127

## v3.4.4 (2024050900)
## Fixed
  * Fixed problems new recordings table
   
 ---

## v3.4.3 (2024050900)
## Added
 * Breakoutroom options
## Changed
 * Improved adaptation when expanding the window.
 * New Google Api 2.16.0
 
 ---

## v3.4.2 (2024032100)
## Added
 * Attendance user list now linked with user profile
## Fixed
 * Fixes the problem that caused the search filters to not be respected when turning pages.
 * Fix error writing to the database when creating a new jitsi activity when inviteopcions is activated #126
 * Fix the URL is not valid when jitsi_id is first name + lasta name or alias #125
## Changed
 * New function normalizesessionname for normalize session name.

---

## v3.4.1 (2024022800)
### Added
 * Attendance user list now linked with user profile
 * Attendance info show minutes today
### Fixed
 * Fix problem with end date and start date on shared sessions
 * Show acces button on form universal when user is logged
 * Fix problem with search pagination when search with user or recorder filter
### Changed
 * New explication for external link on configuration page
 * Pagination for attendees table

---

## v3.4 (2023020900)
### Added
 * Add user and recorder filter for search recordings
 * Add latency parameter
 * New capability for view records. 
 * Add startwithaudiomuted and startwithvideomuted parameters
### Fixed
 * Private sessions error.
 * Url validation for username.
### Changed
 * New mode for share sessions on courses. Now if you want to share a session between two or more courses you have to copy the token that you will find on the configuration page and enter it in the course where you want to share it.
 * URL link for guest users now is on configuration page. 
 * New Google Api 2.15.3
 * Refactoring doembedable function

---

## v3.3.9 (2023102300)
### Added 
* Show course on search videos page
* Add max participants assistant in search result
* Add log url in error mail
* New set recordings not for kids #122. (Pay attention to this new parameter. Before this update the videos were marked as suitable for children. If you want to continue marking videos with this restriction, please activate this option. By default it is disabled.)
### Fixed
* Delete mod_jitsi_delete_recordsource service from services #121
* Index.php corrections. (visibility, table, etc...)
* Delete title and description for v4.0
* Fix for cross-version compatibility, the $flags parameter should be explicitly set
* Add boostrap video responsive for videos on search page
* Fix redirect to login page when enter with link.
* Fix problem when edit record title
* Fix error with str_replace. Replace numbers.
### Changed
* User on search page is firstname and lastname. Username is on tooltip
* Update records with no participants on recordings on air page
* Add footer for link pages if is loggedin and delete intro for 4
* Order at mod_jitsi_inplace_editable.
* Better presentation videos recording on search page

---

## v3.3.4 (2023062700)
### Added
* Round Robin: Add rotating shift queue for recordings. Recordings are now distributed among all session recordings if they are in the queue.
* Link to user profile on recording search page
* Mail to admin when doembeable get an error
### Fixed
* Fix problem with log error on doembedable function
* delete mod_jitsi_delete_recordsource service from services (#121)
### Changed
* Google api client to 2.15.0
* Search page for recordings now show thumbnails
* Remove heading for better appearence on moodle 4

## v3.3.3 (2023052400)
### Added
* Add page with search recordings for administrators

---

## v3.3.2 (2023050300)
### Added
* Add page with live recordings for administrators
* Recordings are locked by the user who started them. Preventing others from stopping them.
* IMPORTANT: new Scheduled tasks is enabled by default in order to delete recordings that are marked
  as deleted by teachers and new setting are included to set the retention period. Disable this task
  if you prefer to manually delete YouTube recordings.
* New section on settings for news and updates information.
* Max number of participants of a seession recorded is saved in source_record table.

### Fixed
* Fixed url for recordings to delete
* Fixed error with return create_stream function 

### Changed
* Pagination for the "Recordings available to delete" list.
* New view with tabs for recordings, help and participanting resume
* Recordings that don't have a link to the recording are not displayed on the jitsi page
* Google api 2.13.1 version
* Access buton now is primary button
* new getclientgoogleapi function to get the google api client
* Switch to record not visible for users without capability
* Help tab is always visible

---

## v3.3 (2022122300)
### Fixed
* Fix problem with timecreated when it's first time
* Solves problems with the French language.
### Changed
* Improvement in the counting of participants

---

## v3.3 (2022122300)
### Added
* New status field for better error handling in recordings
### Fixed
* Added timeclose and timeopen to coursemodule info
* Fixed validitytime check
### Changed
* New version Google api v.2.13.0

---

## v3.2.18 (2022111900)
### Added
* Whiteboard added
### Fixed
* Fixed double competibility output on view.php for moodles v>311
* Fixes issue where teachers couldn't assign capabilities
* #110 Plugin v.3.2.17 does not work when jitsi_password is configurated
### Changed
* Disables all invite functions from the app
* Embedable value based on youtube response

---

## v3.2.17 (2022110701)
### Added
* Add gues link information in mod_form and view page
* New capabilities deleterecord and editrecordname
### Fixed
* Fixed exception - Call to undefined method admin_settingpage::hide_if() on versions less than 37
* Fixed problems with special characteres for chrome 

---

## v3.2.16 (2022101700)
### Added
* Shows the author of a recording in the deleted list
* Add to log when user press button record, cam, microphone, share desktop and end button
* Send mails to admins when record fails
* Register participating when user logged enter with guest link
### Fixed 
* Removes warning when restoring with user data and no recordings
* When making a local recording, the session is being recorded banner is not displayed
* Remove unrecorded videos from jitsi (scheduled videos coming soon)
* Fixes issue where students were triggering the switch to record at 5 seconds
* Fixed Dom Focused problem when copy to clipboard on chrome
* Enable recording service with latest versions of jitsi 
### Changed
* Better handling of api requests
* Disable Grant Moderator button
* Disabled record button when teacher enter with guest link
 
---

## v3.2.11 (2022070601)
### Added
* When a teacher marks a video as deleted it should be hidden on youtube. #105
### Fixed 
* The message that the session has not started appears wrong when accessing through invite #102
* Jitsis with a lot of recordings takes a long time to load the access page #104 
* get_objectid_mapping function missing when importing logs #106
### Changed
* Data type mismatch in name field of jitsi_record table RDM #107

---

## v3.2.8 (2022061600)
### Added
* New version api google (v2.12.6)
### Fixed 
* Ilegal character with substr function #100
* Missing language string #81

---

## v3.2.7 (2022060100)
### Added
* New version api google (v2.12.4)
* Validate link invitation with startdate #98
* Added compatibility with 8x8 servers
### Changed
* jitsi_channellastcam deprecated

---

## v3.2.5 (2022041800)
### Changed
* Some strings to strings file
### Fixed
* Fixed 'core_completion\cm_completion_details' not found on moodle v<311 #93
* Fixed session with long names records #94

---

## v3.2.4 (2022041800)
### Changed
* Clean code api php Google. Lower size plugin
* Corrections moodle style guideliness
### Fixed
* Fixed destructure property on chrome

---

## v3.2.3 (2022041300)
### Fixed
* Remove mdl prefix in sql userconnected

---

## v3.2.2 (2022041300)

### Added
* Moodle 4.0 compatibility
### Fixed
* Remove mdl prefix in getminutes function

---

## v3.2.0 ()
### Added
* Multi-account support for recordings.
* Notification when the user enters a private session.
* Allows guest users in a session. These guests can be users with a site account or without an account.
* Show the number of participants in a session and show assistance report.
* Add activity completion with number of minutes in a session.
* Better moderation without tokens.
* Allows to hide the Raise Hand Button.
* Jitsi reactions.
* Participants panel.
### Changed
* The recording button is replaced by a switch
* Default cameras now are 15.
* Watermark link now are deprecated.
* Enable as default the jitsi_invitebuttons, jitsifinishandreturn, jitsi_blurbutton, jitsi_reactions and jitsi_shareyoutube options in config.
* Only users with mod/jitsi:record should be able to launch native drop box recordings.
* Better placed introduction text and help text.
* Minutes to acces now apply only for users with moderation capability.
* Update Google Api Client to Version 2.12.1
### Fixed
* Background options 
* Fixed problem mod_jitsi_external::create_link implementation is missing

---

## v3.1.2 (2021090100)
* Add validity time for link invitations

---

## v3.1.2 (2021072300)
* Fixed problem with Google API and https sites
