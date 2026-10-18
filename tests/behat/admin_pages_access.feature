@mod @mod_jitsi
Feature: Admin-only pages reject non-admin users
  In order to protect site-wide recording accounts and settings
  As a site administrator
  I need non-admin users to be blocked from mod_jitsi admin pages
  and an administrator to still be able to open them

  # require_admin() renders Moodle's permissions error for a normal user.
  # Behat fails a scenario when that error page is shown, so the rejection
  # is covered by tests/admin_pages_access_test.php. These scenarios check
  # the administrator can still open each page, including the YouTube OAuth
  # script and the search page linked from the plugin settings.

  Scenario Outline: An admin can open an admin page
    Given I log in as "admin"
    When I visit "<page>"
    Then I should see "<text>"

    Examples:
      | page                                     | text                    |
      | /mod/jitsi/auth.php?name=TestAccount     | jitsi_oauth_id          |
      | /mod/jitsi/search.php                    | Recorders               |
      | /mod/jitsi/adminaccounts.php             | Add account             |
      | /mod/jitsi/adminrecord.php               | available to be deleted |
      | /mod/jitsi/recordingmatrix.php           | No recordings available |

  Scenario: An admin reaches recording search from the plugin settings
    Given I log in as "admin"
    And I visit "/admin/settings.php?section=modsettingjitsi"
    When I click on "Search recordings" "link"
    Then I should see "Recorders"
