<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * English strings for jitsi
 *
 * You can have a rather longer description of the file as well,
 * if you like, and it can span multiple lines.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['access'] = 'Access';
$string['accessto'] = 'Access to {$a}. Enter the name to be displayed.';
$string['accesstotitle'] = 'Access to {$a}';
$string['accesstowithlogin'] = 'Access to {$a}.';
$string['account'] = 'Account';
$string['accountconnected'] = 'Account successfully connected and put <b>in use</b>.';
$string['accountinsufficientprivileges'] = 'The streaming account set up has insufficient privileges. Please contact your administrator.';
$string['accounts'] = 'Streaming/Recording Accounts';
$string['action'] = 'Action';
$string['actions'] = 'Actions';
$string['activatetooltip'] = 'Click to put into use';
$string['addaccount'] = 'Add account';
$string['addedtoqueue'] = 'Added to queue';
$string['addnewserver'] = 'Add new server';
$string['addtoqueue'] = 'Add to queue';
$string['adminaccountex'] = 'At least one account is required in order to stream/record sessions with the "Moodle integrated" method for streaming.
 </br>Just one account can be "<b>in use</b>" and will be used to stream/record the next recording demanded by one teacher.
 </br>When adding new accounts it\'s recommended <b>to name them with real account names</b> because in the future you could be required to re-login in order to re-authorize the account.
 </br>Only accounts with no recordings related to teacher\'s Jitsi activities and no recordings pending to be deleted from the streaming servers can be removed here using the trash icon.
 </br>New accounts without credentials could appear here when Jitsi activities backups from other server are restored in this one with accounts that was not present here.
 </br></br>NEW from v3.3.3: a new column called "In queue" allows use all your recorders in round robin. You can add recorders to the queue clicking on "<b>+</b>" and you can remove them from the queue clicking on "<b>-</b>". When a recorder has been used because it was the recorder "<b>in use</b>" (or the next one to be used), the flag "In use" will be set to the next recorder in the queue. This feature allows you to use many recorders in order to avoid YouTube quota limits like the live streams allowed per day.';
$string['alertacceswithlogin'] = 'You are accessing through an external link and you are logged in, please access from the course.';
$string['alias'] = 'Alias';
$string['allow'] = 'Start of videoconference';
$string['allowbreakoutrooms'] = 'Allow breakout rooms';
$string['allowbreakoutroomsex'] = 'Allow to create breakout rooms. Server needs to be configured to allow breakout rooms.';
$string['apikeyid8x8'] = 'Api Key ID';
$string['apikeyid8x8ex'] = 'Api Key ID to use with 8x8 server. You can get it from the 8x8 server administration. (https://jaas.8x8.com/)';
$string['appaccessinfo'] = 'If you want to join the meeting using a mobile device, you will need the Jitsi Meet mobile application.';
$string['appid'] = 'App_ID';
$string['appidex'] = 'App ID for token configuration';
$string['appinstalledtext'] = 'If you already have the app:';
$string['appnotinstalledtext'] = "If you don't have the app yet:";
$string['attendeesreport'] = 'Attendees report';
$string['authq'] = 'Login with this account to get credentials and put "in use"?';
$string['avg_recordings_per_day'] = 'Average Recordings per Day';
$string['avg_recordings_per_week'] = 'Average Recordings per Week';
$string['backtosettings'] = 'Back to settings';
$string['blurbutton'] = 'Show Background options';
$string['blurbuttonex'] = 'Show the "Select Backgroud" option to all users. This feature is cool but require powerfull computers. Maybe you should disable it.';
$string['buttondownloadapp'] = 'Download application';
$string['buttonopeninbrowser'] = 'Open in browser';
$string['buttonopenwithapp'] = 'Join this meeting using the app';
$string['calendarstart'] = 'The videoconference \'{$a}\' start';
$string['click'] = 'Click';
$string['close'] = 'Finish of videoconference';
$string['closebeforeopen'] = 'Could not update the session. You have specified a close date before the open date.';
$string['completiondetail:minutes'] = 'Attend {$a} minutes';
$string['completionminutes'] = 'Student must attend ';
$string['completionminutes_help'] = 'Number of minutes that student must attend to give the activity as completed';
$string['completionminutesex'] = 'Minutes to attend ';
$string['config'] = 'Configuration';
$string['confignewexpirationtime'] = 'Config new expiration time on settings';
$string['confirmdelete'] = 'Are you sure you want to delete the server "{$a}"?';
$string['confirmdeleterecordinactivity'] = 'Confirm you want to delete this recording. This operation can\'t be undone.';
$string['connectedattendeesnow'] = 'Connected attendees now';
$string['copied'] = 'Copied to clipboard';
$string['crontaskdelete'] = 'Delete recordings';
$string['deeplink'] = 'Deep Link';
$string['deeplinkex'] = 'When on moodle app allows to transfer Jitsi sessions to Jitsi app.';
$string['deleteq'] = 'Delete and disconect this acco?';
$string['deleterecord'] = 'Delete record';
$string['deletesourceq'] = 'Are you sure? The recording will be permanently deleted from the video server and it can not be recovered';
$string['deletesources'] = 'Recordings available to delete';
$string['deletetooltip'] = 'Delete';
$string['deprecated'] = 'Deprecated';
$string['deprecatedex'] = 'Deprecated params that probably will not work because Jitsi Meet changed its implementation';
$string['desktopaccessinfo'] = 'If you want to join the meeting, click on the button below to open Jitsi in your browser.';
$string['domain'] = 'Domain';
$string['domainex'] = 'Domain Jitsi Server to use. Default server (<b>meet.jit.si</b>) have a time limit of 5 minutes per conference.
 You can search in Google for alternative public Jitsi servers that could be nearest to your users and with less latency.
 If you have your private own Jitsi Server inform it here without "https://".
 The 8x8 professional server uses to be (<b>8x8.vc</b>) and requires to config your credentials in the bellow "Token Configuration" section.';
$string['editrecordname'] = 'Edit record name';
$string['editserver'] = 'Editar servidor';
$string['entersession'] = 'Enter to session';
$string['error'] = 'Error';
$string['errordeleting'] = 'Error deleting';
$string['exitsession'] = 'Exit session';
$string['experimental'] = 'Experimental';
$string['experimentalex'] = 'These are options that we are experimenting with and that may disappear in future versions.';
$string['externalinvitations'] = 'External invitations';
$string['externaltoken'] = 'External token';
$string['externaltoken_help'] = 'Use this link for guests who don\'t have a Moodle user to access.';
$string['finish'] = 'The session has finished.';
$string['finishandreturn'] = 'Finish and Return';
$string['finishandreturnex'] = 'Return to course when finish the session. Using public Jitsi users return to course when they close advertising';
$string['finishinvitation'] = 'Invitation link will expire on';
$string['forkids'] = 'For kids';
$string['forkidsex'] = 'Recordings will be deemed to have been created for children.';
$string['from'] = 'From';
$string['guestform'] = 'Enter to guest form';
$string['hasentered'] = 'has entered on your private Jitsi session';
$string['help'] = 'Help';
$string['helpex'] = 'This help text customizes the help tab text in Jitsi activities. It\'s a good place for netiquette rules or user help instructions.';
$string['here'] = 'here';
$string['identification'] = 'ID User';
$string['identificationex'] = 'ID to show in the session';
$string['inqueue'] = 'In queue';
$string['instruction'] = 'Click the button to access';
$string['integrated'] = 'Moodle Integrated';
$string['internalerror'] = 'Internal error. Contact with the administrator.';
$string['inuse'] = ' <b>(in use)</b>';
$string['invitations'] = 'Invitations';
$string['invitationsnotactivated'] = 'The invitations is not activated';
$string['invitebutton'] = 'Invite Options';
$string['invitebuttonex'] = 'Allow users with the mod/jitsi:createlink capability (teachers) to create invite links for users not enroled in the course.';
$string['iscalling'] = 'is calling you to enter on his private Jitsi';
$string['jitsi'] = 'Jitsi';
$string['jitsi:addinstance'] = 'Add a new Jitsi';
$string['jitsi:createlink'] = 'View and copy invite links for guest users';
$string['jitsi:deleterecord'] = 'Delete record';
$string['jitsi:editrecordname'] = 'Edit record name';
$string['jitsi:hide'] = 'Hide recordings';
$string['jitsi:moderation'] = 'Jitsi Moderation';
$string['jitsi:record'] = 'Record session';
$string['jitsi:sharedesktop'] = 'Share Desktop';
$string['jitsi:view'] = 'View Jitsi';
$string['jitsi:viewexternallink'] = 'View external link';
$string['jitsi:viewrecords'] = 'View records';
$string['jitsi:viewusersonsession'] = 'Access to the attendees reports';
$string['jitsi_recording_statistics'] = 'Jitsi Recording Statistics';
$string['jitsiinterface'] = 'Jitsi interface';
$string['jitsiname'] = 'Session name';
$string['joinmeeting'] = 'Join meeting';
$string['latency'] = 'Latency';
$string['latencyex'] = 'Select latency level for streaming.';
$string['link'] = 'link';
$string['linkexpiredon'] = 'This link expired on {$a}';
$string['livesessionsnow'] = 'Recordings on air';
$string['loadattendees'] = 'Load attendees';
$string['loadingvideo'] = 'Loading video... Please wait';
$string['loginq'] = 'Do you want to put in use this accout?';
$string['logintooltip'] = 'Credentials for this account are required';
$string['messageprovider:callprivatesession'] = 'Call to Jitsi private';
$string['messageprovider:onprivatesession'] = 'User on private session';
$string['minpretime'] = 'Minutes to access';
$string['minpretime_help'] = 'Users with moderation permissions will be able to access these minutes before the start';
$string['minutesconnected'] = 'You have been connected for {$a} minutes';
$string['minutesday'] = 'Minutes day';
$string['minutestoday'] = 'Minutes today';
$string['modulename'] = 'Jitsi';
$string['modulename_help'] = 'Use the Jitsi module for videoconference. These videoconferences will use your Moodle username by displaying your username and avatar in videoconferences.

Jitsi-meet is an open-source videoconferencing solution that enables you to easily build and implement secure video conferencing solutions.';
$string['modulenameplural'] = 'Jitsis';
$string['myprivatesession'] = 'My private session';
$string['nameandsurname'] = 'Firstname + Lastname';
$string['newvaluefor'] = 'New value for ';
$string['noinviteaccess'] = 'Guest access is currently not allowed.';
$string['nojitsis'] = 'No Jitsi activities found';
$string['norecording'] = 'There is no recording. The video will appear automatically';
$string['norecords'] = 'No recordings available';
$string['nostart'] = 'The session has not started. You can access {$a}';
$string['notloggedin'] = 'Account credentials required';
$string['noviewpermission'] = 'You do not have permission for view this Jitsi session';
$string['number_of_recordings'] = 'Number of Recordings';
$string['numbervideosdeleted'] = 'Number of videos to delete';
$string['numbervideosdeletedex'] = 'Number of videos to delete in each execution of the cron task';
$string['oauthid'] = 'OAuth2 id';
$string['oauthidex'] = 'Oauth2 id google account with YouTube Data API v3 enabled and this Authorized redirect URIs <b>\'{$a}\'</b> on Google api console.';
$string['oauthsecret'] = 'OAuth2 secret';
$string['oauthsecretex'] = 'Oauth2 Secret google account';
$string['participantspane'] = 'Participants panel';
$string['participantspaneex'] = 'Show the participants panel to all users. When uncheck only users with Jitsi Moderation capability (mod/jitsi:moderation), usually teachers, can watch the panel.';
$string['participatingsession'] = 'Participating in session';
$string['password'] = 'Password';
$string['passwordex'] = 'Password to secure your sessions. Recommended if you use public server';
$string['pluginadministration'] = 'Jitsi administration';
$string['pluginname'] = 'Jitsi';
$string['preparing'] = 'Preparing. Please wait...';
$string['presscambutton'] = 'Press cam button';
$string['pressdesktopbutton'] = 'Press desktop button';
$string['pressendbutton'] = 'Press end button';
$string['pressmicrophonebutton'] = 'Press microphone button';
$string['pressrecordbutton'] = 'Press the record button';
$string['privacy:metadata:jitsi'] = 'In order to integrate with a Jitsi session, user data needs to be exchanged with that service.';
$string['privacy:metadata:jitsi:avatar'] = 'The avatar is sent from moodle to show to the other users of the Jitsi session';
$string['privacy:metadata:jitsi:username'] = 'The username is sent from moodle to show to the other users of the Jitsi session';
$string['privatekey'] = 'Private key';
$string['privatekeyex'] = 'Private key to sign the token with 8x8 server. You can get it from the 8x8 server administration. (https://jaas.8x8.com/).
Download the private key file and copy the content here.
</br><b>IMPORTANT</b>: remember to update the "Domain" setting to something like <b>8x8.vc</b>';
$string['privatesession'] = '{$a} private session';
$string['privatesessiondisabled'] = 'Private sessions are disabled';
$string['privatesessions'] = 'Private sessions';
$string['privatesessionsex'] = 'Add private sessions to user profiles';
$string['raisehand'] = 'Raise hand button';
$string['raisehandex'] = 'Show the raisehad button to all users. When users raise their hands they can access to the participants panel. If you hide the participants panels may be you should hide this button.';
$string['reactions'] = 'Reactions';
$string['reactionsex'] = 'Shows sound emoticons of applause, surprise, etc ... "Raise hand button" enabled is required';
$string['record'] = 'Record';
$string['recorders'] = 'Recorders';
$string['recordex'] = 'Enable native Jitsi recording options (actually dropbox) to users with mod/jitsi:record capability enabled (teachers). If you set the "Streaming configuration" with the "Moodle integrated" method probably you will want to disable this.';
$string['recordingbloquedby'] = 'The recording is blocked by ';
$string['recordingwasbloquedby'] = 'The user who started this recording is no longer participating in the session. Do you want to stop this recording? It was started by ';
$string['records'] = 'Recordings';
$string['recordsonair'] = 'Recordings on air';
$string['recordtitle'] = 'Record';
$string['removedfromqueue'] = 'Removed from queue';
$string['removefromqueue'] = 'Remove from queue';
$string['search'] = 'Search';
$string['searchrecords'] = 'Search recordings';
$string['secret'] = 'Secret';
$string['secretex'] = 'Secret for token configuration';
$string['securitybutton'] = 'Security Button';
$string['securitybuttonex'] = 'Enables native Jitsi "Security Options" and the "Lobby mode". Probably you should disable this option if you have set a password above because the password will be displayed to users. With token configuration you can experiment with this option';
$string['selectdate'] = 'Select date';
$string['separator'] = 'Separator';
$string['separatorex'] = 'Define the field separator for the session name';
$string['server'] = 'Jitsi server';
$string['serveradded'] = 'Server created successfully.';
$string['serverdeleted'] = 'Server "{$a}" deleted successfully.';
$string['serverdesc'] = 'Choose which Jitsi server will be used.';
$string['servermanagement'] = 'Jitsi servers';
$string['servermanagementdesc'] = 'Click here to manage Jitsi servers';
$string['serverupdated'] = 'Server "{$a}" updated successfully.';
$string['sessiondeleted'] = 'Session shared deleted';
$string['sessionisbeingrecorded'] = 'Session is being recorded';
$string['sessionisbeingrecordingby'] = 'Session is being recorded by {$a}';
$string['sessionnamefields'] = 'Session name fields';
$string['sessionnamefieldsex'] = 'Fields that define the session name';
$string['sessionshared'] = 'Session shared with \'{$a}\' course';
$string['sharedsessionwithtoken'] = 'Session shared with token. Select this to enter the token of the other course';
$string['sharestream'] = 'Share stream with users outside of Moodle (experimental function)';
$string['sharestreamex'] = 'Enable this setting to offer the ability to share the live stream of a session with users outside of Moodle.';
$string['sharetoinvite'] = 'Share this link to invite someone to the session';
$string['showavatars'] = 'Show avatars in Jitsi';
$string['showavatarsex'] = 'Show the avatar of the user in Jitsi. If the user has no profile picture this will load the default profile picture from Moodle instead of the initials Jitsi will show when no picture is set.';
$string['simultaneouscameras'] = 'Simultaneous cameras';
$string['simultaneouscamerasex'] = 'Maximun simultaneous cameras users can see. That could be overriden by your Jitsi server with a lower value. A lot of cameras allowed could overload your clients browsers.';
$string['startwithaudiomuted'] = 'Start with audio muted';
$string['startwithaudiomutedex'] = 'When user connects to the session, the audio will be muted';
$string['startwithvideomuted'] = 'Start with video muted';
$string['startwithvideomutedex'] = 'When user connects to the session, the video will be muted';
$string['staticinvitationlink'] = 'Invitations option';
$string['staticinvitationlinkcapabilityex'] = 'Use this option for guests who don\'t have a Moodle user to access. Only if you have capability mod/jitsi:createlink you can create or modify the invitation link.';
$string['staticinvitationlinkex'] = 'Use this option for guests who don\'t have a Moodle user to access. You can see and copy the link on invitation tab.';
$string['staticinvitationlinkexview'] = 'Share this link for guests who don\'t have a Moodle user to access.';
$string['status'] = 'Status';
$string['streamingandrecording'] = 'Stream & Record';
$string['streamingbutton'] = 'Live Streaming';
$string['streamingbuttonex'] = 'Enable the Live Streaming features to users with mod/jitsi:record capability enabled (teachers). If enabled probably you will want to disable the "record" option above.';
$string['streamingconfig'] = 'Streaming configuration';
$string['streamingconfigex'] = 'Default streaming configuration works "out of the box" and users can stream/record their sessions with their own streaming accounts in streaming services (Youtube, Peertube...) but teacher is responsible to publish their watch links to students in the course. </br></br>For a better experience you can enable the "Moodle integrated" method in order to record in a corporate stream account (only YouTube available now) and recordings will be automatically available for students.';
$string['streamingisstarting'] = 'Streaming is starting. Please wait...';
$string['streamingoption'] = 'Live Streaming Method';
$string['streamingoptionex'] = '<b>Jitsi interface</b> enable the "Start Live Streming" in the Jitsi interface and users can use their own streaming accounts. </br><b>Moodle integrated</b> is the easyest option for users. Teachers can start a "Record & Stream" inmediatly and no credetials account will be required to them. Stremings/Recordings are stored in a corporate account and will be available inmediatly for students. You must set OAuth2 credentials and a streming account bellow.';
$string['tablelistjitsis'] = "List with all the videos in your Streaming/Recording Accounts providers which are available to be deleted because they are no more linked in Jitsi activities in this moodle instance. You can safely delete them in order to free up space on the streaming server. The list could include videos that now are in the 'Recycle bin' in some course. It's recommended to delete just old recordings that you know won't be required. </br></br> <b>¡¡¡ WARNING!!! </b>If you have moodle backup instances you should NOT remove these videos if they are linked in other instances.";
$string['timeopen'] = 'Session time open';
$string['to'] = 'To';
$string['toenter'] = 'to enter';
$string['token'] = 'Share this token on the other course';
$string['tokenconfiguration8x8ex'] = 'If you use 8x8 servers you need to configure the following parameters.';
$string['tokenconfigurationex'] = 'If you are using a Jitsi server configured in "token mode", for example your own server or an 8x8 server, fill in the following parameters depending on the type of server you are using. Required to promote your users with the (mod/jitsi:moderation) capability enabled as native Jitsi moderators.';
$string['tokeninterno'] = 'Main session token';
$string['tokeninternocompartir'] = 'Token to share';
$string['tokeninternocompartir_help'] = 'Use this token to share the session with other courses. Enter this token in this section of the other course.';
$string['tokeninvitacion'] = 'Enter here the token of the session you want to join';
$string['tokeninvitacion_help'] = 'Enter here the token of the session you want to join. Get this token on the other course.';
$string['tokeninvitadovalidation'] = 'Token not valid';
$string['tokeninvitationnotvalid'] = 'The invitation cannot expire before now';
$string['tokeninvitationvalidation'] = 'Token not valid. There is no session with this token';
$string['tokennconfig'] = 'Token configuration';
$string['tokennconfig8x8'] = '8x8 Servers configuration';
$string['top_10_teachers'] = 'Top 10 Teachers';
$string['toplimit'] = 'Top Limit';
$string['total_participants'] = 'Total Participants';
$string['total_recordings'] = 'Total Recordings';
$string['totalminutes'] = 'Total minutes';
$string['type'] = 'Type';
$string['unknowntype'] = 'Unknown type';
$string['updated'] = 'Updated';
$string['urlerror'] = 'The URL is not valid';
$string['urlinvitacion'] = 'Invitation URL';
$string['urlinvitacionrecord'] = 'Invitation URL for stream';
$string['usercall'] = '{$a} calls you for a private Jitsi';
$string['userenter'] = '{$a} is on your private Jitsi Room';
$string['username'] = 'Username';
$string['validitytimevalidation'] = 'The invitation cannot expire before the session start date or after the session end date.';
$string['videoexpiry'] = 'Retention period';
$string['videoexpiryex'] = 'Time a deleted video will be available in the streaming server. After this time the video will be deleted from the streaming server.';
$string['warningprivate'] = 'If you access, {$a} will be warned with a notification.';
$string['watermarklink'] = 'Watermark Link';
$string['watermarklinkex'] = 'Watermark Link';
$string['whiteboard'] = 'Whiteboard';
$string['whiteboardex'] = 'Show the whiteboard button to all users. Actually Whiteboard is not available on Jaas Servers.';
$string['youtubebutton'] = 'Youtube sharing option';
$string['youtubebuttonex'] = 'Show the youtube videos sharing option';

// --- Google Cloud (GCP) integration strings ---
$string['gcpheading'] = 'Google Cloud (GCP)';
$string['gcpheadingex'] = 'Configure the project and VM where the shared Jitsi server will be deployed.';
$string['gcpproject'] = 'Project ID';
$string['gcpprojectex'] = 'Google Cloud project ID (e.g. my-project).';
$string['gcpzone'] = 'Zone';
$string['gcpzoneex'] = 'Compute Engine zone (e.g. europe-west1-b).';
$string['gcpmachinetype'] = 'Machine type';
$string['gcpmachinetypeex'] = 'Compute Engine machine type (e.g. e2-standard-4).';
$string['gcpimage'] = 'Base image';
$string['gcpimageex'] = 'Image to use for the VM (default: Debian 12 family).';
$string['gcpnetwork'] = 'Network';
$string['gcpnetworkex'] = 'VPC/network to attach the instance to (e.g. global/networks/default).';
$string['gcphostname'] = 'Hostname (FQDN)';
$string['gcphostnameex'] = 'Fully-qualified domain name that will point to the VM (required for Let\'s Encrypt).';
$string['gcpleemail'] = 'Let\'s Encrypt email';
$string['gcpleemailex'] = 'Email address used to request the Let\'s Encrypt certificate.';
$string['gcpstartupscript'] = 'Startup script';
$string['gcpstartupscriptex'] = 'cloud-init/bash script to install and configure Jitsi on first boot.';
$string['gcpserviceaccountjsonfile'] = 'Service Account JSON';
$string['gcpserviceaccountjsonfileex'] = 'Upload the Service Account JSON with permissions to manage Compute Engine.';

// Buttons / actions / notifications for GCP creation.
$string['creategcpserver'] = 'Create server in Google Cloud';
$string['gcpapimissing'] = 'Google Cloud PHP library (google/apiclient) not found. Install it to create servers in GCP.';
$string['gcpsettingsmissing'] = 'Missing GCP settings: {$a}';
$string['gcpservercreated'] = 'Google Cloud server created: {$a}';
$string['gcpservercreatefail'] = 'Failed to create Google Cloud server: {$a}';
$string['gcpoperationerror'] = 'Google Cloud operation error: {$a}';
$string['gcpoperationtimeout'] = 'Google Cloud operation timed out.';

// Default server selection.
$string['serversetasdefault'] = 'Server "{$a}" set as default';
$string['setdefault'] = 'Set as default';

$string['creatingvm'] = 'Creating VM… ({$a})';
$string['gcpcreatingmodal'] = 'Creating virtual machine in Google Cloud';
$string['gcpcreatingwait'] = 'Please wait while the virtual machine is being created. This may take a few minutes.';
$string['gcpcreationerror'] = 'An error occurred while creating the Google Cloud VM: {$a}';
$string['gcpcreationdone'] = 'Google Cloud VM successfully created: {$a}';