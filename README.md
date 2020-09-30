G Suite is an integrated suite of secure, cloud-native collaboration and productivity apps powered by Google AI. G Suite includes Gmail, Docs, Drive, Calendar, Meet and other apps. This integration helps you to perform various tasks on Gmail, Drive, Calendar and users with IAM solutions.
This integration was integrated and tested majorly with G Suite Basic edition.  Command gsuite-license-update is not fully tested. 
The below commands were only tested in the G Suite Enterprise edition.

| **Command Name** |
| --- |
| gsuite-drive-create |
| gsuite-drive-changes-list |
| gsuite-drive-activity-list |

## Configure G Suite on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for G Suite.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| isFetch | Fetch incidents | False |
| user_service_account_json | User's Service Account JSON | True |
| user_id | User ID | False |
| action_detail_case_include | Action Detail Case Include | False |
| action_detail_case_exclude | Action Detail Case Exclude | False |
| drive_item_search_field | Drive Item Search Field | False |
| drive_item_search_value | Drive Item Search Value | False |
| max_fetch | Max Incidents | False |
| first_fetch | First Fetch Time Interval | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gsuite-delegate-create
***
Gives email and contact access for the given users to the specified delegate account. Adds a delegate with its verification status set directly to 'accepted', without sending any verification email. The delegate and the delegator must be in the same domain, granting delegate access across multiple domains is currently not possible.


#### Base Command

`gsuite-delegate-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| delegate_to | The email address of the delegate. | Required | 
| delegate_from | The email address of the delegator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Delegate.delegateEmail | String | The email address of the delegate. | 
| GSuite.Delegate.delegatorEmail | String | The email address of the delegator. | 
| GSuite.Delegate.verificationStatus | String | Indicates whether the address has been verified and can act as a delegate for the account. | 


#### Command Example
```!gsuite-delegate-create delegate_from=delegatefrom@domain.com delegate_to=delegateto@domain.com```

#### Context Example
```
{
    "GSuite": {
        "Delegate": {
            "delegateEmail": "delegateto@domain.com",
            "delegatorEmail": "delegatefrom@domain.com",
            "verificationStatus": "accepted"
        }
    }
}
```

#### Human Readable Output

>Giving delegatefrom@domain.com delegate access to delegateto@domain.com.

### gsuite-vacation-update
***
Enables or disables vacation/away messages for users. It helps to set away/vacation message subject and text.


#### Base Command

`gsuite-vacation-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User's email address.  | Required | 
| vacation | Enable or disable vacation responder for the given user. | Required | 
| subject | Sets the away/vacation subject for the given user. Mandatory, if vacation mode is On and message is not provided. | Optional | 
| message | Sets the away/vacation message for the given user. Mandatory, if vacation mode is On and message is not provided. Message has higher precedence than message_entry_id when both arguments are provided. | Optional | 
| message_entry_id | Sets the away/vacation message by passing a War room entryID of the file for the given user. | Optional | 
| start_time | Sets a start date for the vacation message to be enabled for the given user. Valid format- YYYY-MM-DD or Epoch time in milliseconds. | Optional | 
| end_time | Sets an end date for the vacation message to be enabled for the given user. Valid format- YYYY-MM-DD or Epoch time in milliseconds. | Optional | 
| contacts_only | Allows to send away/vacation messages to users in contact list when set to True. | Optional | 
| domain_only | Prevent sending away/vacation messages to recipients who are outside of the user's domain when set to True. | Optional | 
| message_type | Sets message response body type to text or HTML. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Vacation.userId | String | User's email address. | 
| GSuite.Vacation.enableAutoReply | Boolean | Flag that controls whether Gmail automatically replies to messages. | 
| GSuite.Vacation.responseSubject | String | Text to prepend to the subject line in vacation responses. | 
| GSuite.Vacation.responseBodyPlainText | String | Response body in plain text format. | 
| GSuite.Vacation.responseBodyHtml | String | Response body in HTML format. | 
| GSuite.Vacation.restrictToContacts | Boolean | Flag that determines whether responses are sent to recipients who are not in the user's list of contacts. | 
| GSuite.Vacation.restrictToDomain | Boolean | Flag that determines whether responses are sent to recipients who are outside of the user's domain. | 
| GSuite.Vacation.startTime | Number | Start time for sending auto-replies. | 
| GSuite.Vacation.endTime | Number | End time for sending auto-replies. | 


#### Command Example
```!gsuite-vacation-update user_id=user@domain.com vacation=On domain_only=True message="test vacation on"```

#### Context Example
```
{
    "GSuite": {
        "Vacation": {
            "enableAutoReply": true,
            "responseBodyPlainText": "test vacation on",
            "restrictToContacts": false,
            "restrictToDomain": true,
            "userId": "user@domain.com"
        }
    }
}
```

#### Human Readable Output

>### Vacation settings updated for user id - user@domain.com.
>|Body Plain Text|Restrict To Contacts|Restrict To Domain|Enable Auto Reply|
>|---|---|---|---|
>| test vacation on | false | true | true |


### gsuite-filter-create
***
Creates a filter for the given user. Filter must have at least one criteria and at least one action. Criteria includes to, from, query, negated_query, subject, exclude_chats, has_attachment, size and size_comparison. Action includes forward, add_label_ids, and remove_label_ids.


#### Base Command

`gsuite-filter-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User's email address. | Required | 
| to | The recipient's display name or email address. Includes recipients in the "to", "cc", and "bcc" header fields. | Optional | 
| from | The sender's display name or email address. | Optional | 
| subject | Case-insensitive phrase found in the message's subject. Trailing and leading whitespace are trimmed and adjacent spaces are collapsed. | Optional | 
| query | Only return messages matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid:&lt;somemsgid@example.com&gt; is:unread". | Optional | 
| negated_query | Only return messages not matching the specified query. Supports the same query format as the Gmail search box. For example, "from:someuser@example.com rfc822msgid:&lt;somemsgid@example.com&gt; is:unread". | Optional | 
| has_attachment | Whether the message has any attachment. | Optional | 
| exclude_chats | Whether the response should exclude chats. | Optional | 
| add_label_ids | List of labels to add to the message. | Optional | 
| remove_label_ids | List of labels to remove from the message. | Optional | 
| forward | Email address that the message should be forwarded to. | Optional | 
| size | The size of the entire RFC822 message in bytes, including all headers and attachments. | Optional | 
| size_comparison | How the message size in bytes should be in relation to the size field. Can be SMALLER- Find messages smaller than the given size, LARGER- Find messages larger than the given size, or UNSPECIFIED. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Filter.id | String | The server assigned ID of the filter. | 
| GSuite.Filter.criteria.from | String | The sender's display name or email address. | 
| GSuite.Filter.criteria.to | String | The recipient's display name or email address. | 
| GSuite.Filter.criteria.subject | String | Case-insensitive phrase found in the message's subject. \(Trailing and leading whitespace are trimmed and adjacent spaces are collapsed\) | 
| GSuite.Filter.criteria.query | String | Only return messages matching the specified query. | 
| GSuite.Filter.criteria.negatedQuery | String | Only return messages not matching the specified query. | 
| GSuite.Filter.criteria.hasAttachment | Boolean | Whether the message has any attachment. | 
| GSuite.Filter.criteria.excludeChats | Boolean | Whether the response should exclude chats. | 
| GSuite.Filter.criteria.size | Number | The size of the entire RFC822 message in bytes, including all headers and attachments. | 
| GSuite.Filter.criteria.sizeComparison | String | How the message size in bytes should be in relation to the size field. | 
| GSuite.Filter.action.addLabelIds | Unknown | List of labels to add to the message. | 
| GSuite.Filter.action.removeLabelIds | Unknown | List of labels to remove from the message. | 
| GSuite.Filter.action.forward | String | Email address that the message should be forwarded to. | 
| GSuite.Filter.userId | String | User's email address. | 


#### Command Example
```!gsuite-filter-create user_id=userfilter@domain.com add_label_ids=Label_123456 from=userfrom@domain.com size=500```

#### Context Example
```
{
    "GSuite": {
        "Filter": {
            "action": {
                "addLabelIds": [
                    "Label_123456"
                ]
            },
            "criteria": {
                "from": "userfrom@domain.com"
            },
            "id": "ANe1BmjSsEtLvxzmye1llBzFewnxhz2KeXTCrA",
            "userId": "userfilter@domain.com"
        }
    }
}
```

#### Human Readable Output

>### Filter Details
>|Id|User Id|Criteria|Action|
>|---|---|---|---|
>| ANe1BmjSsEtLvxzmye1llBzFewnxhz2KeXTCrA | userfilter@domain.com | From: userfrom@domain.com | Add Label Ids: Label_123456 |


### gsuite-mobile-update
***
Takes an action that affects a mobile device. For example, remotely wiping a device.


#### Base Command

`gsuite-mobile-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | The unique ID of the customer's G Suite account. | Required | 
| resource_id | The unique ID used to identify the mobile device. | Required | 
| action | The action to be performed on the device.<br/><br/>Available Options:<br/>admin_account_wipe - Remotely wipes only G Suite data from the device.<br/><br/>admin_remote_wipe - Remotely wipes all data on the device.<br/><br/>approve - Approves the device.<br/><br/>block - Blocks access to G Suite data on the device.<br/><br/>cancel_remote_wipe_then_activate - Cancels a remote wipe of the device and then reactivates it.<br/><br/>cancel_remote_wipe_then_block - Cancels a remote wipe of the device and then blocks it. | Required | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` 
!gsuite-mobile-update resource_id=RESOURCE_ID  action=admin_account_wipe customer_id=my_customer admin_email=admin@domain.io
```

#### Human Readable Output
> Mobile device with resource id - RESOURCE_ID updated.


### gsuite-mobile-delete
***
Removes a mobile device. Note that this does not break the device's sync, it simply removes it from the list of devices connected to the domain. If the device still has a valid login/authentication, it will be added back on it's next successful sync.


#### Base Command

`gsuite-mobile-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | The unique ID of the customer's G Suite account. | Required | 
| resource_id | The unique ID used to identify the mobile device. | Required | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gsuite-mobile-delete customer_id=my_customer resource_id=AFFIQUAU-Adjghah-rezwed admin_email=adminemail@domain.com```


#### Human Readable Output

>Mobile device with resource id - AFFIQUAU-Adjghah-rezwed deleted.

### gsuite-forwarding-address-add
***
Creates a forwarding address. If ownership verification is required, a message will be sent to the recipient and the resource's verification status will be set to pending; otherwise, the resource will be created with verification status set to accepted. This method is only available to service account clients that have been delegated domain-wide authority.


#### Base Command

`gsuite-forwarding-address-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| forwarding_email | An email address to which messages can be forwarded. | Required | 
| user_id | User's email address. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.ForwardingAddress.forwardingEmail | String | An email address to which messages can be forwarded. | 
| GSuite.ForwardingAddress.userId | String | User's email address. | 
| GSuite.ForwardingAddress.verificationStatus | String | Indicates whether this address has been verified and is usable for forwarding. | 


#### Command Example
``` 
!gsuite-forwarding-address-add forwarding_email=user1@test.com user_id=user2@test.com
```


#### Context Example
```
{
"GSuite":{
   "ForwardingAddress": {
     "forwardingEmail": "user1@test.com",
     "verificationStatus": "accepted",
     "userId": "user2@test.com"
   }
 }
```


#### Human Readable Output
>Added forwarding address user1@test.com for user2@test.com with status accepted.


### gsuite-send-as-add
***
Creates a custom "from" send-as alias. If an SMTP MSA is specified, Gmail will attempt to connect to the SMTP service to validate the configuration before creating the alias. If ownership verification is required for the alias, a message will be sent to the email address and the resource's verification status will be set to pending; otherwise, the resource will be created with verification status set to accepted. If a signature is provided, Gmail will sanitize the HTML before saving it with the alias.

This command is only available to service account clients that have been delegated domain-wide authority.


#### Base Command

`gsuite-send-as-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User's email address. | Required | 
| send_as_email | The email address that appears in the "From:" header for mail sent using this alias. | Required | 
| display_name | A name that appears in the "From:" header for mail sent using this alias. For custom "from" addresses, when this is empty, Gmail will populate the "From:" header with the name that is used for the primary address associated with the account. If the admin has disabled the ability for users to update their name format, requests to update this field for the primary login will silently fail. | Optional | 
| signature | An optional HTML signature that is included in messages composed with this alias in the Gmail web UI. | Optional | 
| reply_to_address | An optional email address that is included in a "Reply-To:" header for mail sent using this alias. If this is empty, Gmail will not generate a "Reply-To:" header. | Optional | 
| is_default | Whether this address is selected as the default "From:" address in situations such as composing a new message or sending a vacation auto-reply. Every Gmail account has exactly one default send-as address, so the only legal value that clients may write to this field is true. Changing this from false to true for an address will result in this field becoming false for the other previous default address. | Optional | 
| treat_as_alias | Whether Gmail should treat this address as an alias for the user's primary email address. This setting only applies to custom "from" aliases. | Optional | 
| smtp_host | The hostname of the SMTP service. Required for smtp configuration. | Optional | 
| smtp_port | The port of the SMTP service. Required for smtp configuration. | Optional | 
| smtp_username | The username that will be used for authentication with the SMTP service. This is a write-only field that can be specified in requests to create or update SendAs settings. | Optional | 
| smtp_password | The password that will be used for authentication with the SMTP service. This is a write-only field that can be specified in requests to create or update SendAs settings. | Optional | 
| smtp_securitymode | The protocol that will be used to secure communication with the SMTP service. Required for smtp configuration.<br/><br/>Available Options:<br/>SECURITY_MODE_UNSPECIFIED - Unspecified security mode.<br/><br/>NONE - Communication with the remote SMTP service is unsecured. Requires port 25.<br/><br/>SSL - Communication with the remote SMTP service is secured using SSL.<br/><br/>STARTTLS - Communication with the remote SMTP service is secured using STARTTLS. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.SendAs.userId | String | User's email address. | 
| GSuite.SendAs.sendAsEmail | String | The updated send-as alias. | 
| GSuite.SendAs.signature | String | An optional HTML signature that is included in messages composed with this alias in the Gmail web UI. | 
| GSuite.SendAs.isPrimary | Boolean | Whether this address is the primary address used to login to the account. | 
| GSuite.SendAs.isDefault | Boolean | Whether this address is selected as the default "From:" address in situations. | 
| GSuite.SendAs.treatAsAlias | Boolean | Whether Gmail should treat this address as an alias for the user's primary email address. | 
| GSuite.SendAs.smtpMsaHost | String | The hostname of the SMTP service. | 
| GSuite.SendAs.smtpMsaPort | String | The port of the SMTP service. | 
| GSuite.SendAs.smtpMsaSecurityMode | String | The protocol that will be used to secure communication with the SMTP service. | 
| GSuite.SendAs.verificationStatus | String | Indicates whether this address has been verified for use as a send-as alias. | 
| GSuite.SendAs.replyToAddress | String | A name that appears in the "From:" header for mail sent using this alias. | 


#### Command Example
``` 
!gsuite-send-as-add send_as_email="sample@test.io" display_name="sample_name" is_default=true 
reply_to_address="reply_here@test.io" signature="<h1> some_signature </h1>" treat_as_alias=true 
user_id="sample_user@test.io"
```


#### Human Readable Output

>### A custom "sample@test.io" send-as alias created for "sample_user@test.io".
>|Send As Email|Display Name|Reply To Address|Treat As Alias|
>|---|---|---|---|
>| sample@test.io | sample_name | reply_here@test.io | true|


#### Context Example
``` 
{
 "GSuite": {
   "SendAs": {
     "displayName": "sample_name",
     "isDefault": true,
     "replyToAddress": "reply_here@test.io",
     "sendAsEmail": "sample@test.io",
     "signature": "<h1> some_signature </h1>",
     "treatAsAlias": true,
     "verificationStatus": "accepted",
     "userId": "sample_user@test.io"
   }
 }
}
```


### gsuite-acl-add
***
Creates an access control rule.


#### Base Command

`gsuite-acl-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| calendar_id | Identifier of the calendar. If you want to access the primary calendar of the currently logged in user, use the "primary" keyword. | Required | 
| user_id | The user's primary email address. | Optional | 
| role | The role assigned to the scope.<br/><br/>Available Options:<br/>none - Provides no access.<br/><br/>freeBusyReader - Provides read access to free/busy information.<br/><br/>reader - Provides read access to the calendar. Private events will appear to users with reader access, but event details will be hidden.<br/><br/>writer - Provides read and write access to the calendar. Private events will appear to users with writer access, and event details will be visible.<br/><br/>owner - Provides ownership of the calendar. This role has all of the permissions of the writer role with the additional ability to see and manipulate ACLs. | Required | 
| scope_type | The type of the scope.<br/><br/>Available Options:<br/>default - The public scope. This is the default value.<br/><br/>user - Limits the scope to a single user.<br/><br/>group - Limits the scope to a group.<br/><br/>domain - Limits the scope to a domain.<br/><br/>Note: The permissions granted to the "default", or public, scope apply to any user, authenticated or not. | Required | 
| scope_value | The email address of a user or group, or the name of a domain, depending on the scope type. Omitted for type "default". | Optional | 
| send_notifications | Use the optional send_notifications flag to choose whether to send notifications about the calendar sharing change or not. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Acl.calendarId | String | Calendar identifier. | 
| GSuite.Acl.id | String | Identifier of the ACL rule. | 
| GSuite.Acl.kind | String | Type of the resource. | 
| GSuite.Acl.etag | String | ETag of the resource. | 
| GSuite.Acl.scopeType | String | The type of the scope. | 
| GSuite.Acl.scopeValue | String | The email address of a user or group, or the name of a domain, depending on the scope type. | 
| GSuite.Acl.role | String | The role assigned to the scope. | 


#### Command Example
```!gsuite-acl-add calendar_id=calenderId role=freeBusyReader scope_type=user scope_value=useracl@domain.com user_id=user1@domain.com```


#### Context Example
```
{
    "GSuite": {
        "Acl": {
            "calendarId": "calenderId",
            "etag": "\"00001600760672577000\"",
            "id": "user:useracl@domain.com",
            "kind": "calendar#aclRule",
            "role": "freeBusyReader",
            "scopeType": "user",
            "scopeValue": "useracl@domain.com"
        }
    }
}
```

#### Human Readable Output

>### Giving an access control rule for calendar id "calenderId".
>|Id|Role|Scope Type|Scope Value|
>|---|---|---|---|
>| user:useracl@domain.com | freeBusyReader | user | useracl@domain.com |


### gsuite-user-alias-add
***
Adds an alias.


#### Base Command

`gsuite-user-alias-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_key | Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID. | Required | 
| alias | The alias email address. | Required | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.UserAlias.kind | String | The type of the API resource. | 
| GSuite.UserAlias.id | String | The unique ID for the user. | 
| GSuite.UserAlias.etag | String | ETag of the resource. | 
| GSuite.UserAlias.alias | String | The alias email address. | 


#### Command Example
```!gsuite-user-alias-add alias=alias_321@domain.com user_key=demoaccount@domain.com admin_email=user1@domain.com```

#### Context Example
```
{
    "GSuite": {
        "UserAlias": {
            "alias": "alias_321@domain.com",
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/jJ5Cz1VAIrUEoGZlaiop-HTSKJ4\"",
            "id": "108028652821197762751",
            "kind": "admin#directory#alias"
        }
    }
}
```

#### Human Readable Output

>Added alias "alias_321@domain.com" to user key "demoaccount@domain.com".

### gsuite-drive-create
***
Creates a new Team Drive. The name argument specifies the name of the Team Drive. The specified user will be the first organizer.
This shared drive/team drive feature is available only with G Suite Enterprise, Enterprise for Education, G Suite Essentials, Business, Education, and Nonprofits edition.


#### Base Command

`gsuite-drive-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's primary email address. | Optional |
| name | The name of this shared drive. | Required | 
| hidden | Whether the shared drive is hidden from default view. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Drive.kind | String | Identifies what kind of resource this is. | 
| GSuite.Drive.id | String | The ID of this shared drive which is also the ID of the top level folder of this shared drive. | 
| GSuite.Drive.name | String | The name of this shared drive. |
| GSuite.Drive.hidden | Boolean | Whether the shared drive is hidden from default view. |


#### Command Example
``` 
!gsuite-drive-create name=drive1
```

#### Context Example
```
{
 "GSuite": {
   "Drive": {
     "kind": "drive#drive",
     "id": "YYg1BVyzlZx",
     "name": "drive1",
     "hidden": true
   }
 }
} 
```

#### Human Readable Output
>### A new shared drive created.
>|Id|Name|Hidden|
>|---|---|---|
>| YYg1BVyzlZx | drive1 | true |


### gsuite-user-create
***
Creates a user.


#### Base Command

`gsuite-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The user's first name. | Required | 
| last_name | The user's last name. | Required | 
| password | Stores the password for the user account. A password can contain any combination of ASCII characters. A minimum of 8 characters is required. The maximum length is 100 characters. The password will be sent in MD5 hash format. | Required | 
| primary_email | The user's primary email address. The primary_email must be unique and cannot be an alias of another user. | Required | 
| country | User's Country. | Optional | 
| address_type | The address type. | Optional | 
| postal_code | The ZIP or postal code, if applicable. | Optional | 
| is_address_primary | Set to true, If this is the user's primary address. | Optional | 
| extended_address | For extended addresses, such as an address that includes a sub-region. | Optional | 
| region | The abbreviated province or state. | Optional | 
| street_address | The street address, such as 1600 Amphitheatre Parkway. Whitespace within the string is ignored; however, newlines are significant. | Optional | 
| secondary_email_address | The user's secondary email address. | Optional | 
| secondary_email_type | The type of the secondary email account. | Optional | 
| gender | User's gender. | Optional | 
| is_ip_white_listed | If true, the user's IP address is white listed. | Optional | 
| notes_content_type | Content type of note, either plain text or HTML. If not provided, considered as plain text. | Optional | 
| notes_value | Contents of notes. | Optional | 
| phone_number | A human-readable phone number. It may be in any telephone number format. | Optional | 
| phone_number_type | The type of phone number. | Optional | 
| is_phone_number_primary | Indicates if this is the user's primary phone number. A user may only have one primary phone number. | Optional | 
| recovery_email | Recovery email of the user. | Optional | 
| recovery_phone | Recovery phone of the user. The phone number must be in the E.164 format, starting with the plus sign (+). Example: +16506661212. | Optional | 
| suspended | Indicates if the user is suspended. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.User.id | String | The unique ID for the user. | 
| GSuite.User.primaryEmail | String | The user's primary email address. | 
| GSuite.User.firstName | String | The user's first name. | 
| GSuite.User.lastName | String | The user's last name. | 
| GSuite.User.customerId | String | The unique ID for the customer's G Suite account. | 
| GSuite.User.gender | String | Gender. | 
| GSuite.User.suspended | Boolean | Indicates if the user is suspended. | 
| GSuite.User.notesValue | String | Contents of notes. | 
| GSuite.User.notesContentType | String | Content type of notes. | 
| GSuite.User.isAdmin | Boolean | Indicates a user with super administrator privileges. | 
| GSuite.User.creationTime | Date | The time the user's account was created. | 
| GSuite.User.phones.value | String | A human-readable phone number. It may be in any telephone number format. | 
| GSuite.User.phones.type | String | The type of phone number. | 
| GSuite.User.phones.primary | String | Indicates if this is the user's primary phone number. | 
| GSuite.User.addresses.type | String | The address type. | 
| GSuite.User.addresses.country | String | Country. | 
| GSuite.User.addresses.postalCode | String | The ZIP or postal code. | 
| GSuite.User.addresses.region | String | The abbreviated province or state. | 
| GSuite.User.addresses.streetAddress | String | The street address. | 
| GSuite.User.addresses.extendedAddress | String | For extended addresses, such as an  address that includes a sub-region. | 
| GSuite.User.addresses.primary | Boolean | If this is the user's primary address. | 
| GSuite.User.emails.address | String | The user's secondary email. | 
| GSuite.User.emails.type | String | The secondary email type. | 
| GSuite.User.ipWhitelisted | Boolean | If true, the user's IP address is white listed. | 
| GSuite.User.recoveryEmail | String | Recovery email of the user. | 
| GSuite.User.isDelegatedAdmin | Boolean | Indicates if the user is a delegated administrator. | 
| GSuite.User.recoveryPhone | String | Recovery phone of the user. | 
| GSuite.User.orgUnitPath | String | The full path of the parent organization associated with the user. If the parent organization is the top-level, it is represented as a forward slash \(/\). | 
| GSuite.User.isMailboxSetup | Boolean | Indicates if the user's Google mailbox is created. | 
| GSuite.User.kind | Boolean | The type of the API resource. | 
| GSuite.User.etag | Boolean | ETag of the resource. | 
| GSuite.User.hashFunction | String | Stores the hash format of the password property. | 


#### Command Example
```!gsuite-user-create admin_email=adminemail@domain.com first_name="new" last_name="user" primary_email="new.user@domain.com" password="user@123"```

#### Context Example
``` 
{
 "GSuite":{
       "User": {
           "creationTime": "2020-09-22T11:26:26.000Z",
           "customerId": "C03puekhd",
           "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/4tvQSgzvpG3jXKVblT3Ey-0_slk\"",
           "firstName": "new",
           "hashFunction": "MD5",
           "id": "111364427621472798290",
           "isAdmin": false,
           "isDelegatedAdmin": false,
           "isMailboxSetup": false,
           "kind": "admin#directory#user",
           "lastName": "user",
           "orgUnitPath": "/",
           "primaryEmail": "new.user@domain.com"
       }
   }
}
```

#### Human Readable Output

>### User Details
>|Id|Customer Id|Primary Email|First Name|Last Name|Is Admin|Creation Time|
>|---|---|---|---|---|---|---|
>| 111364427621472798290 | C03puekhd | new.user@domain.com | new | user | false | 2020-09-22T11:26:26.000Z |


### gsuite-acl-list
***
Returns the rules in the access control list for the calendar.


#### Base Command

`gsuite-acl-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| calendar_id | Calendar identifier. If you want to access the primary calendar of the currently logged in user, use the "primary" keyword. | Required | 
| user_id | The user's primary email address. | Optional | 
| max_results | Maximum number of entries returned on one result page. By default the value is 100 entries. The page size can never be larger than 250 entries. | Optional | 
| page_token | Token specifying which result page to return. | Optional | 
| show_deleted | Whether to include deleted ACLs in the result. Deleted ACLs are represented by role equal to "none". Deleted ACLs will always be included if syncToken is provided. | Optional | 
| sync_token | Token obtained from the nextSyncToken field returned on the last page of results from the previous list request. It makes the result of this list request contain only entries that have changed since then. All entries deleted since the previous list request will always be in the result set and it is not allowed to set showDeleted to False.<br/>If the syncToken expires, the server will respond with a 410 GONE response code and the client should clear its storage and perform a full synchronization without any syncToken.<br/> | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Acl.calendarId | String | Calendar identifier. | 
| GSuite.Acl.id | String | Identifier of the ACL rule. | 
| GSuite.Acl.kind | String | Type of the resource. | 
| GSuite.Acl.etag | String | ETag of the resource. | 
| GSuite.Acl.scopeType | String | The type of the scope. | 
| GSuite.Acl.scopeValue | String | The email address of a user or group, or the name of a domain, depending on the scope type. | 
| GSuite.Acl.role | String | The role assigned to the scope. | 
| GSuite.PageToken.Acl.calendarId | String | Calendar identifier. | 
| GSuite.PageToken.Acl.nextPageToken | String | Token used to access the next page of this result. | 
| GSuite.PageToken.Acl.nextSyncToken | String | Token used at a later point in time to retrieve only the entries that have changed since this result was returned. | 


#### Command Example
```!gsuite-acl-list calendar_id=calenderID user_id=user1@domain.com max_results=2```

#### Context Example
```
{
    "GSuite": {
        "Acl": [
            {
                "calendarId": "calenderID",
                "etag": "\"00000000000000000000\"",
                "id": "user:user1@domain.com",
                "kind": "calendar#aclRule",
                "role": "owner",
                "scopeType": "user",
                "scopeValue": "user1@domain.com"
            },
            {
                "calendarId": "calenderID",
                "etag": "\"00001598621012848000\"",
                "id": "user:xxxx@domain.com",
                "kind": "calendar#aclRule",
                "role": "reader",
                "scopeType": "user",
                "scopeValue": "xxxx@domain.com"
            }
        ],
        "PageToken": {
            "Acl": {
                "calendarId": "calenderID",
                "nextPageToken": "EKiDnZGM_OsCGAAgADIkCgwI1Iqk-gUQgOitlAMSFCoSeHh4eEBuaW1ibGVkYXRhLmlv"
            }
        }
    }
}
```

#### Human Readable Output

>### Next Page Token: EKiDnZGM_OsCGAAgADIkCgwI1Iqk-gUQgOitlAMSFCoSeHh4eEBuaW1ibGVkYXRhLmlv
>### Total Retrieved ACL: 2
>|Id|Role|Scope Type|Scope Value|
>|---|---|---|---|
>| user:user1@domain.com | owner | user | user1@domain.com |
>| user:xxxx@domain.com | reader | user | xxxx@domain.com |


### gsuite-group-create
***
Creates a group with a group name and its description.


#### Base Command

`gsuite-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_email | The group's email address. | Required | 
| group_name | The group's display name. | Optional | 
| group_description | An extended description to help users determine the purpose of a group. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Group.kind | String | The type of the API resource. | 
| GSuite.Group.id | String | The unique ID of a group. | 
| GSuite.Group.etag | String | ETag of the resource. | 
| GSuite.Group.email | String | The group's email address. | 
| GSuite.Group.name | String | The group's display name. | 
| GSuite.Group.directMembersCount | String | The number of users that are direct members of the group. | 
| GSuite.Group.description | String | An extended description to help users determine the purpose of a group. | 
| GSuite.Group.adminCreated | Boolean | Value is true if this group was created by an administrator rather than a user. | 
| GSuite.Group.aliases | String | List of a group's alias email addresses. | 
| GSuite.Group.nonEditableAliases | String | List of the group's non-editable alias email addresses that are outside of the account's primary domain or subdomains. | 


#### Command Example
```!gsuite-group-create group_email="testsgroup@domain.com" admin_email=adminemail@domain.com group_description="group description"```

#### Context Example
```
{
    "GSuite": {
        "Group": {
            "adminCreated": true,
            "description": "group description",
            "email": "testsgroup@domain.com",
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/LI8IDdZB9k7tBdClkZja0jnTX9k\"",
            "id": "017dp8vu2zdcnpe",
            "kind": "admin#directory#group",
            "name": "testsgroup"
        }
    }
}
```

#### Human Readable Output

>### A new group named "testsgroup" created.
>|Id|Email|Description|Admin Created|
>|---|---|---|---|
>| 017dp8vu2zdcnpe | testsgroup@domain.com | group description | true |


### gsuite-role-assignment-list
***
Retrieves a paginated list of all role assignments.


#### Base Command

`gsuite-role-assignment-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Immutable ID of the G Suite account. | Required | 
| role_id | Immutable ID of a role. If included, it returns only role assignments containing this role ID. | Optional | 
| user_key | The user's primary email address, alias email address, or unique user ID. If included in the request, returns role assignments only for this user. | Optional | 
| page_token | Token to specify the next page in the list. | Optional | 
| max_results | Maximum number of results to return. Acceptable values are 1 to 200, inclusive. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.RoleAssignment.kind | String | The type of the API resource. | 
| GSuite.RoleAssignment.etag | String | ETag of the resource. | 
| GSuite.RoleAssignment.roleAssignmentId | Number | ID of this role assignment. | 
| GSuite.RoleAssignment.roleId | Number | The ID of the role that is assigned. | 
| GSuite.RoleAssignment.assignedTo | String | The unique ID of the user this role is assigned to. | 
| GSuite.RoleAssignment.scopeType | String | The scope in which this role is assigned. | 
| GSuite.RoleAssignment.orgUnitId | String | If the role is restricted to an organization unit, this contains the ID of the organization unit to which the exercise of this role is restricted to. | 
| GSuite.PageToken.RoleAssignment.nextPageToken | String | Token to specify the next page in the list. | 


#### Command Example
```!gsuite-role-assignment-list customer_id=my_customer admin_email=adminemail@domain.com max_results=2 user_key=112697610```

#### Context Example
```
{
    "GSuite": {
        "PageToken": {
            "RoleAssignment": {
                "nextPageToken": "1380118834"
            }
        },
        "RoleAssignment": [
            {
                "assignedTo": "112697610",
                "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/HNRTxaa_Vj5uoXcenlvlCaLm5ZM\"",
                "kind": "admin#directory#roleAssignment",
                "roleAssignmentId": "1380118833",
                "roleId": "1380118839",
                "scopeType": "CUSTOMER"
            },
            {
                "assignedTo": "112697610",
                "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/AjrcWjoYFdv8ZnxLMYDX7UhbA3w\"",
                "kind": "admin#directory#roleAssignment",
                "roleAssignmentId": "1380118834",
                "roleId": "1380118838",
                "scopeType": "CUSTOMER"
            }
        ]
    }
}
```

#### Human Readable Output

>### Next Page Token: 1380118834
>### Total Retrieved Role Assignment(s): 2
>|Role Assignment Id|Role Id|Assigned To|Scope Type|
>|---|---|---|---|
>| 1380118833 | 1380118839 | 112697610 | CUSTOMER |
>| 1380118834 | 1380118838 | 112697610 | CUSTOMER |


### gsuite-role-assignment-create
***
Creates a role assignment.


#### Base Command

`gsuite-role-assignment-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Immutable ID of the G Suite account. | Required | 
| role_id | The ID of the role to be assigned to the user. | Required | 
| assigned_to | The unique ID of the user this role is assigned to. | Required | 
| scope_type | The scope in which this role is assigned. | Required | 
| org_unit_id | If the role is restricted to an organization unit, this contains the ID for the organization unit the exercise of this role is restricted to. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.RoleAssignment.kind | String | The type of the API resource. | 
| GSuite.RoleAssignment.etag | String | ETag of the resource. | 
| GSuite.RoleAssignment.roleAssignmentId | Number | ID of this role assignment. | 
| GSuite.RoleAssignment.roleId | Number | The ID of the role that is assigned. | 
| GSuite.RoleAssignment.assignedTo | String | The unique ID of the user this role is assigned to. | 
| GSuite.RoleAssignment.scopeType | String | The scope in which this role is assigned. | 
| GSuite.RoleAssignment.orgUnitId | String | If the role is restricted to an organization unit, this contains the ID of the organization unit to which the exercise of this role is restricted to. | 


#### Command Example
```!gsuite-role-assignment-create assigned_to=112697610 customer_id=my_customer role_id=13801188331880450 scope_type=CUSTOMER admin_email=adminemail@domain.com```

#### Context Example
```
{
    "GSuite": {
        "RoleAssignment": {
            "assignedTo": "112697610",
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/bSzQO50Ycd4Fn6ibBqIioX4qhj0\"",
            "kind": "admin#directory#roleAssignment",
            "roleAssignmentId": "331880504",
            "roleId": "13801188331880450",
            "scopeType": "CUSTOMER"
        }
    }
}
```

#### Human Readable Output

>### Role Assignment Details
>|Role Assignment Id|Role Id|Assigned To|Scope Type|
>|---|---|---|---|
>| 331880504 | 13801188331880450 | 112697610 | CUSTOMER |


### gsuite-user-license-update
***
Reassign a user's product SKU with a different SKU in the same product.  (SKU- Stock Keeping Unit) [beta]


#### Base Command

`gsuite-user-license-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | A product's unique identifier. For more information about products in this version of the API, see https://developers.google.com/admin-sdk/licensing/v1/how-tos/products. | Required | 
| old_sku_id | A product's old SKU's unique identifier. For more information about available SKUs in this version of the API, see https://developers.google.com/admin-sdk/licensing/v1/how-tos/products. | Required | 
| user_id | The user's current primary email address. | Required | 
| new_sku_id | A product's new SKU's unique identifier. For more information about available SKUs in this version of the API, see https://developers.google.com/admin-sdk/licensing/v1/how-tos/products. | Required | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.License.kind | String | Identifies the resource as a license assignment. | 
| GSuite.License.etags | String | ETag of the resource. | 
| GSuite.License.userId | String | The user's current primary email address. | 
| GSuite.License.selfLink | String | Link to this page. | 
| GSuite.License.productId | String | A product's unique identifier. | 
| GSuite.License.skuId | String | A product SKU's unique identifier. | 
| GSuite.License.skuName | String | Display Name of the sku of the product. | 
| GSuite.License.productName | String | Display Name of the product. | 


#### Command Example
``` 
!gsuite-user-license-update new_sku_id=1010020020 product_id=Google-Apps user_id=user@domain.io old_sku_id=Google-Apps-For-Business 
admin_email=admin@domain.io
```


#### Command Example
``` 
{
 "GSuite": {
   "License": {
     "kind": "licensing#licenseAssignment",
     "etags": "etag",
     "selfLink": "link",
     "userId": "user@domain.io",
     "productId": "Google-Apps",
     "skuId": "1010020020",
     "skuName": "G Suite Enterprise",
     "productName": "G Suite"
   }
 }
}
```


#### Human Readable Output

>### Updated User License Details
>|Product Id|Product Name|SKU Id|SKU Name|User Id|
>|---|---|---|---|---|
>| Google-Apps | G Suite | 1010020020 | G Suite Enterprise | user@domain.io |


### gsuite-role-create
***
Creates a new role.


#### Base Command

`gsuite-role-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Immutable ID of the G Suite account. | Required | 
| role_name | Name of the role. | Required | 
| role_privileges | The set of privileges that are granted to this role. Comma-separated list of privilege names and service ids of the form "PrivilegeName1:ServiceId1,PrivilegeName2:ServiceId2". | Required | 
| role_description | A short description of the role. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.Role.kind | String | The type of the API resource. This is always admin\#directory\#role. | 
| GSuite.Role.etag | String | ETag of the resource. | 
| GSuite.Role.roleId | Number | ID of the role. | 
| GSuite.Role.roleName | String | Name of the role. | 
| GSuite.Role.roleDescription | String | A short description of the role. | 
| GSuite.Role.rolePrivileges.privilegeName | String | The name of the privilege. | 
| GSuite.Role.rolePrivileges.serviceId | String | The obfuscated ID of the service this privilege is for. | 
| GSuite.Role.isSystemRole | Boolean | Whether this is a pre-defined system role. | 
| GSuite.Role.isSuperAdminRole | Boolean | Whether the role is a super admin role. | 


#### Command Example
``` 
!gsuite-role-create customer_id=my_customer role_name role_privileges="PRIVILEGE_NAME:service_id" 
admin_email=admin@domain.com
```


#### Context Example
``` 
{
 "GSuite": {
   "Role": {
     "kind": "admin#directory#role",
     "etag": "\"XVqXMfEoKXKeCEJHh6Z_d9s0pNqKA90jMskGKajpbM8/JL5ppEimKvC4Ue7Bfhb0qv7Ahqw\"",
     "roleId": "13801188331880469",
     "roleName": "role_22345",
     "rolePrivileges": [
       {
         "privilegeName": "PRIVILEGE_NAME",
         "serviceId": "service_id"
       }
     ]
   }
 }
}
```


#### Human Readable Output

>### A new role created.
>|Id|Name|Privileges|
>|---|---|---|
>| 13801188331880469 | role_22345 | PRIVILEGE_NAME: service_id |


### gsuite-token-revoke
***
Delete all access tokens issued by a user for an application.


#### Base Command

`gsuite-token-revoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_id | The Client ID of the application the token is issued to. | Required | 
| user_key | Identifies the user in the API request. The value can be the user's primary email address, alias email address, or unique user ID. | Required | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gsuite-token-revoke client_id=297408095146-fug707qsjv4ikron0hugpevbrjhkmsk7.apps.googleusercontent.com user_key=user1@domain.com admin_email=adminemail@domain.com```


#### Human Readable Output

>All access tokens deleted for 297408095146-fug707qsjv4ikron0hugpevbrjhkmsk7.apps.googleusercontent.com.


### gsuite-datatransfer-list
***
Lists the transfers for a customer by source user, destination user, or status.


#### Base Command

`gsuite-datatransfer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| customer_id | Immutable ID of the G Suite account. | Optional | 
| new_owner_user_id | Destination user's profile ID. | Optional | 
| old_owner_user_id | Source user's profile ID. | Optional | 
| status | Status of the transfer. | Optional | 
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 
| max_results | Maximum number of results to return. Default is 100. Acceptable values are 1 to 500, inclusive. | Optional | 
| page_token | Token to specify the next page in the list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.DataTransfer.kind | String | Identifies the resource as a DataTransfer request. | 
| GSuite.DataTransfer.etag | String | ETag of the resource. | 
| GSuite.DataTransfer.id | String | The transfer's ID. | 
| GSuite.DataTransfer.oldOwnerUserId | String | ID of the user whose data is being transferred. | 
| GSuite.DataTransfer.newOwnerUserId | String | ID of the user to whom the data is being transferred. | 
| GSuite.DataTransfer.overallTransferStatusCode | String | Overall transfer status. | 
| GSuite.DataTransfer.requestTime | Date | The time at which the data transfer was requested. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferStatus | String | Current status of transfer for this application. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationId | Number | The application's ID. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferParams.key | String | The type of the transfer parameter. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferParams.value | Unknown | The value of the corresponding transfer parameter. | 
| GSuite.PageToken.DataTransfer.nextPageToken | String | Continuation token which will be used to specify next page in list API. | 


#### Command Example
```!gsuite-datatransfer-list admin_email=adminemail@domain.com customer_id=my_customer max_results=2```

#### Context Example
```
{
    "GSuite": {
        "DataTransfer": [
            {
                "applicationDataTransfers": [
                    {
                        "applicationId": "55656082996",
                        "applicationTransferParams": [
                            {
                                "key": "PRIVACY_LEVEL",
                                "value": [
                                    "PRIVATE",
                                    "SHARED"
                                ]
                            }
                        ],
                        "applicationTransferStatus": "completed"
                    }
                ],
                "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/a30QB7XJOzBUhwPRCWCP1g2o7do\"",
                "id": "AKrEtIYG88pek5zyrIzBx7kV5g4JNiUshLFkMbPUYKXsTgRGIJvAyjpzpti9I38WXJ70t6ef0fUIx0EM82KfN_PPP7KKNfHeSQ",
                "kind": "admin#datatransfer#DataTransfer",
                "newOwnerUserId": "103744886667034914950",
                "oldOwnerUserId": "111046242590772774691",
                "overallTransferStatusCode": "completed",
                "requestTime": "2020-09-14T06:30:55.672Z"
            },
            {
                "applicationDataTransfers": [
                    {
                        "applicationId": "55656082996",
                        "applicationTransferParams": [
                            {
                                "key": "PRIVACY_LEVEL",
                                "value": [
                                    "PRIVATE",
                                    "SHARED"
                                ]
                            }
                        ],
                        "applicationTransferStatus": "completed"
                    }
                ],
                "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/SAQmSzZJLc6bhvvGfKFwlvsd_Fg\"",
                "id": "AKrEtIYG88pek5zyrIzBx7kV5g4Jha32YbTTHrbqLTPGaiqmLKuA3WFU7zyxmmkwUrGZcf73dt4SAcDmj5_GeCgoCRFJWbyIxg",
                "kind": "admin#datatransfer#DataTransfer",
                "newOwnerUserId": "103744886667034914950",
                "oldOwnerUserId": "111046242590772774691",
                "overallTransferStatusCode": "completed",
                "requestTime": "2020-09-14T06:31:01.051Z"
            }
        ],
        "PageToken": {
            "DataTransfer": {
                "nextPageToken": "AKrEtIYG88pek5zyrIzBx7kV5g4Jha32YbTTHrbqLTPGaiqmLKuA3WFU7zyxmmkwUrGZcf73dt4SAcDmj5_GeCgoCRFJWbyIxg"
            }
        }
    }
}
```

#### Human Readable Output

>### Next Page Token: AKrEtIYG88pek5zyrIzBx7kV5g4Jha32YbTTHrbqLTPGaiqmLKuA3WFU7zyxmmkwUrGZcf73dt4SAcDmj5_GeCgoCRFJWbyIxg
>
>### Total Retrieved Data Transfers: 2
>|Id|Old Owner User Id|New Owner User Id|Overall Transfer Status Code|Request Time|Application Data Transfers|
>|---|---|---|---|---|---|
>| AKrEtIYG88pek5zyrIzBx7kV5g4JNiUshLFkMbPUYKXsTgRGIJvAyjpzpti9I38WXJ70t6ef0fUIx0EM82KfN_PPP7KKNfHeSQ | 111046242590772774691 | 103744886667034914950 | completed | 2020-09-14T06:30:55.672Z | Application Id: 55656082996<br/>Application Transfer Status: completed<br/><br/> |
>| AKrEtIYG88pek5zyrIzBx7kV5g4Jha32YbTTHrbqLTPGaiqmLKuA3WFU7zyxmmkwUrGZcf73dt4SAcDmj5_GeCgoCRFJWbyIxg | 111046242590772774691 | 103744886667034914950 | completed | 2020-09-14T06:31:01.051Z | Application Id: 55656082996<br/>Application Transfer Status: completed<br/><br/> |


### gsuite-custom-user-schema-create
***
Creates a custom user schema to add custom fields to user profiles.
Note: field_raw_json has higher precedence when both field_raw_json and field_json_entry_id are provided.


#### Base Command

`gsuite-custom-user-schema-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 
| customer_id | Immutable ID of the G Suite account. | Required | 
| schema_name | The schema's name. | Required | 
| schema_display_name | Display name for the schema. | Required | 
| field_raw_json | Raw JSON containing fields of the schema. Acceptable values for<br/>fieldType are BOOL, DATE, DOUBLE, EMAIL, INT64, PHONE, and STRING. Acceptable<br/>values for readAccessType are ADMINS_AND_SELF- Only administrators and<br/>the associated user can see values, and ALL_DOMAIN_USERS- Any user in<br/>your domain can see values.<br/>E.g.<br/>{<br/>  "fields": [<br/>    {<br/>      "fieldType": string,<br/>      "fieldName": string,<br/>      "displayName": string,<br/>      "multiValued": boolean,<br/>      "readAccessType": string,<br/>      "indexed": boolean,<br/>      "numericIndexingSpec": {<br/>        "minValue": double,<br/>        "maxValue": double<br/>      }<br/>    }<br/>  ]<br/>}<br/> | Optional | 
| field_json_entry_id | JSON file entry ID containing fields of the schema. Acceptable values for<br/>fieldType are BOOL, DATE, DOUBLE, EMAIL, INT64, PHONE, and STRING. Acceptable<br/>values for readAccessType are ADMINS_AND_SELF- Only administrators and<br/>the associated user can see values, and ALL_DOMAIN_USERS- Any user in<br/>your domain can see values.<br/>E.g.<br/>{<br/>  "fields": [<br/>    {<br/>      "fieldType": string,<br/>      "fieldName": string,<br/>      "displayName": string,<br/>      "multiValued": boolean,<br/>      "readAccessType": string,<br/>      "indexed": boolean,<br/>      "numericIndexingSpec": {<br/>        "minValue": double,<br/>        "maxValue": double<br/>      }<br/>    }<br/>  ]<br/>}<br/> | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.UserSchema.kind | String | The type of the API resource. | 
| GSuite.UserSchema.etag | String | The ETag of the resource. | 
| GSuite.UserSchema.schemaId | String | The unique identifier of the schema. | 
| GSuite.UserSchema.schemaName | String | The schema's name. | 
| GSuite.UserSchema.displayName | String | Display Name for the schema. | 
| GSuite.UserSchema.fields.kind | String | The kind of resource this is. | 
| GSuite.UserSchema.fields.fieldId | String | The unique identifier of the field. | 
| GSuite.UserSchema.fields.etag | String | The ETag of the field. | 
| GSuite.UserSchema.fields.fieldType | String | The type of the field. | 
| GSuite.UserSchema.fields.fieldName | String | The name of the field. | 
| GSuite.UserSchema.fields.displayName | String | Display name of the field. | 
| GSuite.UserSchema.fields.multiValued | Boolean | A boolean specifying whether this is a multi-valued field or not. | 
| GSuite.UserSchema.fields.readAccessType | Boolean | Specifies who can view values of this field. | 
| GSuite.UserSchema.fields.indexed | Boolean | Specifies whether the field is indexed or not. | 
| GSuite.UserSchema.fields.numericIndexingSpecMinValue | Number | Minimum value of this field. | 
| GSuite.UserSchema.fields.numericIndexingSpecMaxValue | Number | Maximum value of this field. | 


#### Command Example
```!gsuite-custom-user-schema-create customer_id=my_customer schema_display_name=test44 schema_name=schema_name4 admin_email=adminemail@domain.com  field_raw_json="{\"fields\":[{\"fieldType\":\"BOOL\",\"fieldName\":\"surname4\",\"displayName\":\"Surname4\",\"multiValued\":true}]}"```

#### Context Example
```
{
    "GSuite": {
        "UserSchema": {
            "displayName": "test44",
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/MjPzd5dwc-Ht2kOBcz-U0AZNWFA\"",
            "fields": [
                {
                    "displayName": "Surname4",
                    "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/O3s2wxQMfyD89C1J8b2M021ICl4\"",
                    "fieldId": "ltlnHmK5SJGk8zXvNWYA9g==",
                    "fieldName": "surname4",
                    "fieldType": "BOOL",
                    "kind": "admin#directory#schema#fieldspec",
                    "multiValued": true,
                    "readAccessType": "ALL_DOMAIN_USERS"
                }
            ],
            "kind": "admin#directory#schema",
            "schemaId": "5JijaVh6R7ar7zK0u95XSw==",
            "schemaName": "schema_name4"
        }
    }
}
```

#### Human Readable Output

>### Custom User Schema Details
>Schema Id: 5JijaVh6R7ar7zK0u95XSw==
>Schema Name: schema_name4
>Schema Display Name: test44
>### Field Details
>|Field Id|Field Name|Display Name|Field Type|Read Access Type|Multi Valued|
>|---|---|---|---|---|---|
>| ltlnHmK5SJGk8zXvNWYA9g== | surname4 | Surname4 | BOOL | ALL_DOMAIN_USERS | true |


### gsuite-custom-user-schema-update
***
Updates a custom user schema.
Note: field_raw_json has higher precedence when both field_raw_json and field_json_entry_id are provided.


#### Base Command

`gsuite-custom-user-schema-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 
| customer_id | Immutable ID of the G Suite account. | Required | 
| schema_name | The schema's name. | Optional | 
| schema_id | Immutable ID of the schema. | Optional | 
| schema_display_name | Display name for the schema. | Optional | 
| field_raw_json | Raw JSON containing fields of the schema. Acceptable values for<br/>fieldType are BOOL, DATE, DOUBLE, EMAIL, INT64, PHONE, and STRING. Acceptable<br/>values for readAccessType are ADMINS_AND_SELF- Only administrators and<br/>the associated user can see values, and ALL_DOMAIN_USERS- Any user in<br/>your domain can see values.<br/>E.g.<br/>{<br/>  "fields": [<br/>    {<br/>      "fieldType": string,<br/>      "fieldName": string,<br/>      "displayName": string,<br/>      "multiValued": boolean,<br/>      "readAccessType": string,<br/>      "indexed": boolean,<br/>      "numericIndexingSpec": {<br/>        "minValue": double,<br/>        "maxValue": double<br/>      }<br/>    }<br/>  ]<br/>}<br/> | Optional | 
| field_json_entry_id | JSON file entry ID containing fields of the schema. Acceptable values for<br/>fieldType are BOOL, DATE, DOUBLE, EMAIL, INT64, PHONE, and STRING. Acceptable<br/>values for readAccessType are ADMINS_AND_SELF- Only administrators and<br/>the associated user can see values, and ALL_DOMAIN_USERS- Any user in<br/>your domain can see values.<br/>E.g.<br/>{<br/>  "fields": [<br/>    {<br/>      "fieldType": string,<br/>      "fieldName": string,<br/>      "displayName": string,<br/>      "multiValued": boolean,<br/>      "readAccessType": string,<br/>      "indexed": boolean,<br/>      "numericIndexingSpec": {<br/>        "minValue": double,<br/>        "maxValue": double<br/>      }<br/>    }<br/>  ]<br/>}<br/> | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.UserSchema.kind | String | The type of the API resource. | 
| GSuite.UserSchema.etag | String | The ETag of the resource. | 
| GSuite.UserSchema.schemaId | String | The unique identifier of the schema. | 
| GSuite.UserSchema.schemaName | String | The schema's name. | 
| GSuite.UserSchema.displayName | String | Display Name for the schema. | 
| GSuite.UserSchema.fields.kind | String | The kind of resource this is. | 
| GSuite.UserSchema.fields.fieldId | String | The unique identifier of the field. | 
| GSuite.UserSchema.fields.etag | String | The ETag of the field. | 
| GSuite.UserSchema.fields.fieldType | String | The type of the field. | 
| GSuite.UserSchema.fields.fieldName | String | The name of the field. | 
| GSuite.UserSchema.fields.displayName | String | Display name of the field. | 
| GSuite.UserSchema.fields.multiValued | Boolean | A boolean specifying whether this is a multi-valued field or not. | 
| GSuite.UserSchema.fields.readAccessType | Boolean | Specifies who can view values of this field. | 
| GSuite.UserSchema.fields.indexed | Boolean | Specifies whether the field is indexed or not. | 
| GSuite.UserSchema.fields.numericIndexingSpecMinValue | Number | Minimum value of this field. | 
| GSuite.UserSchema.fields.numericIndexingSpecMaxValue | Number | Maximum value of this field. | 


#### Command Example
```!gsuite-custom-user-schema-update customer_id=my_customer admin_email=adminemail@domain.com field_raw_json="{\"fields\":[{\"fieldType\":\"BOOL\",\"fieldName\":\"surname\",\"displayName\":\"Surname\",\"multiValued\":true}]}" schema_id=ZZi9zLU7ROmyBoufhbn9gg== schema_name=test222```

#### Context Example
```
{
    "GSuite": {
        "UserSchema": {
            "displayName": "test222",
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/T3_i5bZrWyPLStFhy3G4vdhHyws\"",
            "fields": [
                {
                    "displayName": "Surname",
                    "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/9vV1znpuuEz23OOT4Vy8K6kMy8A\"",
                    "fieldId": "cMmMeyLxTKyM-7m7bb9Y_Q==",
                    "fieldName": "surname",
                    "fieldType": "BOOL",
                    "kind": "admin#directory#schema#fieldspec",
                    "multiValued": true
                }
            ],
            "kind": "admin#directory#schema",
            "schemaId": "ZZi9zLU7ROmyBoufhbn9gg==",
            "schemaName": "test222"
        }
    }
}
```

#### Human Readable Output

>### Updated Custom User Schema Details
>Schema Id: ZZi9zLU7ROmyBoufhbn9gg==
>Schema Name: test222
>Schema Display Name: test222
>### Field Details
>|Field Id|Field Name|Display Name|Field Type|Multi Valued|
>|---|---|---|---|---|
>| cMmMeyLxTKyM-7m7bb9Y_Q== | surname | Surname | BOOL | true |


### gsuite-datatransfer-request-create
***
Inserts a data transfer request.
Note: If all three applications_raw_json, applications_raw_json_entry_id and application_id are provided
the higher precedence will be in order of applications_raw_json, applications_raw_json_entry_id, 
and application_id respectively.


#### Base Command

`gsuite-datatransfer-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| admin_email | Email ID of the G Suite domain admin acts on behalf of an end-user. | Optional | 
| old_owner_id | ID of the user whose data is being transferred. | Required | 
| new_owner_id | ID of the user to whom the data is being transferred. | Required | 
| application_id | The application's ID. | Optional | 
| application_transfer_params | Key and value pair of application data transfer parameters. Key and value must be delimited by (:) colon. Multiple values must be delimited by (,) comma. Multiple key-value pairs must be delimited by (;) semi-colon. E.g. key1:val;key2:val1,val2 | Optional | 
| applications_raw_json | Raw JSON containing the whole body of the application data transfers.<br/>E.g.<br/>{<br/>  "applicationDataTransfers": [<br/>    {<br/>      "applicationId": long,<br/>      "applicationTransferParams": [<br/>        {<br/>          "key": string,<br/>          "value": [<br/>            string<br/>          ]<br/>        }<br/>      ]<br/>    }<br/>  ]<br/>}<br/> | Optional | 
| applications_raw_json_entry_id | JSON file Entry ID containing the whole body of the application data transfers.<br/>E.g.<br/>{<br/>  "applicationDataTransfers": [<br/>    {<br/>      "applicationId": long,<br/>      "applicationTransferParams": [<br/>        {<br/>          "key": string,<br/>          "value": [<br/>            string<br/>          ]<br/>        }<br/>      ]<br/>    }<br/>  ]<br/>}<br/> | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.DataTransfer.kind | String | Identifies the resource as a DataTransfer request. | 
| GSuite.DataTransfer.etag | String | ETag of the resource. | 
| GSuite.DataTransfer.id | String | The transfer's ID. | 
| GSuite.DataTransfer.oldOwnerUserId | String | ID of the user whose data is being transferred. | 
| GSuite.DataTransfer.newOwnerUserId | String | ID of the user to whom the data is being transferred. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationId | Number | The application's ID. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferParams.key | String | The type of the transfer parameter. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferParams.value | Unknown | The value of the corresponding transfer parameter. | 
| GSuite.DataTransfer.applicationDataTransfers.applicationTransferStatus | String | Current status of transfer for this application. | 
| GSuite.DataTransfer.overallTransferStatusCode | String | Overall transfer status. | 
| GSuite.DataTransfer.requestTime | Date | The time at which the data transfer was requested. | 


#### Command Example
```!gsuite-datatransfer-request-create application_id=435070579839 application_transfer_params="RELEASE_RESOURCES:TRUE" new_owner_id=108028652821197762751 old_owner_id=119443780932332```

#### Context Example
```
{
    "GSuite": {
        "DataTransfer": {
            "applicationDataTransfers": [
                {
                    "applicationId": "435070579839",
                    "applicationTransferParams": [
                        {
                            "key": "RELEASE_RESOURCES",
                            "value": [
                                "TRUE"
                            ]
                        }
                    ],
                    "applicationTransferStatus": "pending"
                }
            ],
            "etag": "\"kUnwYYg1BVyzlZxLWewcY0fcrpfz6LbI3xDE6gsvPl4/pNKVLr3d6L1hPB8f4CoG08y4sSw\"",
            "id": "AKrEtIYCgUCoI7j9IqOCJ2q4HkJUVaZJaYpgSPDEP-GIzkHz3pH1CQuBa-P38vqhSOSuKcJOwPT8GSKhTGDqOw8vJt8FQeTL8Q",
            "kind": "admin#datatransfer#DataTransfer",
            "newOwnerUserId": "108028652821197762751",
            "oldOwnerUserId": "119443780932332",
            "overallTransferStatusCode": "inProgress",
            "requestTime": "2020-09-22T07:44:44.473Z"
        }
    }
}
```

#### Human Readable Output

>### Data transfer request inserted successfully.
>|Id|Old Owner User Id|New Owner User Id|Overall Transfer Status Code|Request Time|Application Data Transfers|
>|---|---|---|---|---|---|
>| AKrEtIYCgUCoI7j9IqOCJ2q4HkJUVaZJaYpgSPDEP-GIzkHz3pH1CQuBa-P38vqhSOSuKcJOwPT8GSKhTGDqOw8vJt8FQeTL8Q | 119443780932332 | 108028652821197762751 | inProgress | 2020-09-22T07:44:44.473Z | Application Id: 435070579839,<br/>Application Transfer Status: pending |


### gsuite-drive-changes-list
***
Lists the changes for a user or shared drive.


#### Base Command

`gsuite-drive-changes-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_token | The token for continuing a previous list request on the next page. | Required | 
| user_id | The user's primary email address. | Optional | 
| drive_id | The shared drive from which changes are returned. | Optional | 
| include_corpus_removals | Whether changes should include the file resource if the file is still accessible by the user at the time of the request, even when a file was removed from the list of changes and there will be no further change entries for this file. | Optional | 
| include_items_from_all_drives | Whether both My Drive and shared drive items should be included in results. | Optional | 
| include_permissions_for_view | Specifies which additional view's permissions to include in the response. Only 'published' is supported. | Optional | 
| include_removed | Whether to include changes indicating that items have been removed from the list of changes, for example by deletion or loss of access. | Optional | 
| page_size | The maximum number of changes to return per page. Acceptable values are 1 to 1000, inclusive. | Optional | 
| restrict_to_my_drive | Whether to restrict the results to changes inside the My Drive hierarchy. This omits changes to files such as those in the Application Data folder or shared files which have not been added to My Drive. | Optional | 
| spaces | A comma-separated list of spaces to query within the user corpus. Supported values are 'drive', 'appDataFolder' and 'photos'. | Optional | 
| supports_all_drives | Whether the requesting application supports both My Drives and shared drives. | Optional | 
| fields | The paths of the fields you want to be included in the response. Option basic will consider a response that includes a default set of fields, specific to this method. While in advance option, special value * will be used which returns all the fields. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.PageToken.DriveChange.nextPageToken | String | The page token for the next page of changes. | 
| GSuite.PageToken.DriveChange.newStartPageToken | String | The starting page token for future changes. | 
| GSuite.PageToken.DriveChange.driveId | String | The ID of the shared drive associated with this change. | 
| GSuite.PageToken.DriveChange.userId | String | The user's primary email address. | 
| GSuite.DriveChange.userId | String | The user's primary email address. | 
| GSuite.DriveChange.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.changeType | String | The type of the change. Possible values are file and drive. | 
| GSuite.DriveChange.time | Date | The time of this change \(RFC 3339 date-time\). | 
| GSuite.DriveChange.removed | Boolean | Whether the file or shared drive has been removed from this list of changes, for example by deletion or loss of access. | 
| GSuite.DriveChange.fileId | String | The ID of the file which has changed. | 
| GSuite.DriveChange.driveId | String | The ID of the shared drive associated with this change. | 
| GSuite.DriveChange.file.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.id | String | The ID of the file. | 
| GSuite.DriveChange.file.name | String | The name of the file. | 
| GSuite.DriveChange.file.mimeType | String | The MIME type of the file. | 
| GSuite.DriveChange.file.description | String | A short description of the file. | 
| GSuite.DriveChange.file.starred | Boolean | Whether the user has starred the file. | 
| GSuite.DriveChange.file.trashed | Boolean | Whether the file has been trashed, either explicitly or from a trashed parent folder. Only the owner may trash a file. | 
| GSuite.DriveChange.file.explicitlyTrashed | Boolean | Whether the file has been explicitly trashed, as opposed to recursively trashed from a parent folder. | 
| GSuite.DriveChange.file.trashingUser.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.trashingUser.displayName | String | A plain text displayable name for this user. | 
| GSuite.DriveChange.file.trashingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.trashingUser.me | Boolean | Whether this user is the requesting user. | 
| GSuite.DriveChange.file.trashingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GSuite.DriveChange.file.trashingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GSuite.DriveChange.file.trashedTime | Date | The time that the item was trashed \(RFC 3339 date-time\). Only populated for items in shared drives. | 
| GSuite.DriveChange.file.parents | Unknown | The IDs of the parent folders which contain the file. | 
| GSuite.DriveChange.file.properties | Unknown | A collection of arbitrary key-value pairs which are visible to all apps. | 
| GSuite.DriveChange.file.appProperties | Unknown | A collection of arbitrary key-value pairs which are private to the requesting app. | 
| GSuite.DriveChange.file.spaces | Unknows | The list of spaces which contain the file. The currently supported values are 'drive', 'appDataFolder' and 'photos'. | 
| GSuite.DriveChange.file.version | Number | A monotonically increasing version number for the file. This reflects every change made to the file on the server, even those not visible to the user. | 
| GSuite.DriveChange.file.webContentLink | String | A link for downloading the content of the file in a browser. This is only available for files with binary content in Google Drive. | 
| GSuite.DriveChange.file.webViewLink | String | A link for opening the file in a relevant Google editor or viewer in a browser. | 
| GSuite.DriveChange.file.iconLink | String | A static, unauthenticated link to the file's icon. | 
| GSuite.DriveChange.file.hasThumbnail | Boolean | Whether this file has a thumbnail. | 
| GSuite.DriveChange.file.thumbnailLink | String | A short-lived link to the file's thumbnail, if available. | 
| GSuite.DriveChange.file.thumbnailVersion | Number | The thumbnail version for use in thumbnail cache invalidation. | 
| GSuite.DriveChange.file.viewedByMe | Boolean | Whether the file has been viewed by this user. | 
| GSuite.DriveChange.file.viewedByMeTime | Date | The last time the file was viewed by the user \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.createdTime | Date | The time at which the file was created \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.modifiedTime | Date | The last time the file was modified by anyone \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.modifiedByMeTime | Date | The last time the file was modified by the user \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.modifiedByMe | Boolean | Whether the file has been modified by this user. | 
| GSuite.DriveChange.file.sharedWithMeTime | Date | The time at which the file was shared with the user, if applicable \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.sharingUser.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.sharingUser.displayName | String | A plain text displayable name for this user. | 
| GSuite.DriveChange.file.sharingUser.photoLink | Date | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.sharingUser.me | Boolean | Whether this user is the requesting user. | 
| GSuite.DriveChange.file.sharingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GSuite.DriveChange.file.sharingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GSuite.DriveChange.file.owners.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.owners.displayName | String | A plain text displayable name for this user. | 
| GSuite.DriveChange.file.owners.photoLink | String | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.owners.me | Boolean | Whether this user is the requesting user. | 
| GSuite.DriveChange.file.owners.permissionId | String | The user's ID as visible in Permission resources. | 
| GSuite.DriveChange.file.owners.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GSuite.DriveChange.file.driveId | String | ID of the shared drive the file resides in. Only populated for items in shared drives. | 
| GSuite.DriveChange.file.lastModifyingUser.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.lastModifyingUser.displayName | String | A plain text displayable name for this user. | 
| GSuite.DriveChange.file.lastModifyingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.lastModifyingUser.me | Boolean | Whether this user is the requesting user. | 
| GSuite.DriveChange.file.lastModifyingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GSuite.DriveChange.file.lastModifyingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GSuite.DriveChange.file.shared | Boolean | Whether the file has been shared. Not populated for items in shared drives. | 
| GSuite.DriveChange.file.ownedByMe | Boolean | Whether the user owns the file. Not populated for items in shared drives. | 
| GSuite.DriveChange.file.capabilities.canAddChildren | Boolean | Whether the current user can add children to this folder. This is always false when the item is not a folder. | 
| GSuite.DriveChange.file.capabilities.canAddFolderFromAnotherDrive | Boolean | Whether the current user can add a folder from another drive \(different shared drive or My Drive\) to this folder. | 
| GSuite.DriveChange.file.capabilities.canAddMyDriveParent | Boolean | Whether the current user can add a parent for the item without removing an existing parent in the same request. Not populated for shared drive files. | 
| GSuite.DriveChange.file.capabilities.canChangeCopyRequiresWriterPermission | Boolean | Whether the current user can change the copyRequiresWriterPermission restriction of this file. | 
| GSuite.DriveChange.file.capabilities.canComment | Boolean | Whether the current user can comment on this file. | 
| GSuite.DriveChange.file.capabilities.canCopy | Boolean | Whether the current user can copy this file. | 
| GSuite.DriveChange.file.capabilities.canDelete | Boolean | Whether the current user can delete this file. | 
| GSuite.DriveChange.file.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children of this folder. This is false when the item is not a folder. Only populated for items in shared drives. | 
| GSuite.DriveChange.file.capabilities.canDownload | Boolean | Whether the current user can download this file. | 
| GSuite.DriveChange.file.capabilities.canEdit | Boolean | Whether the current user can edit this file. | 
| GSuite.DriveChange.file.capabilities.canListChildren | Boolean | Whether the current user can list the children of this folder. This is always false when the item is not a folder. | 
| GSuite.DriveChange.file.capabilities.canModifyContent | Boolean | Whether the current user can modify the content of this file. | 
| GSuite.DriveChange.file.capabilities.canModifyContentRestriction | Boolean | Whether the current user can modify restrictions on content of this file. | 
| GSuite.DriveChange.file.capabilities.canMoveChildrenOutOfDrive | Boolean | Whether the current user can move children of this folder outside of the shared drive. | 
| GSuite.DriveChange.file.capabilities.canMoveChildrenWithinDrive | Boolean | Whether the current user can move children of this folder within this drive. | 
| GSuite.DriveChange.file.capabilities.canMoveItemOutOfDrive | Boolean | Whether the current user can move this item outside of this drive by changing its parent. | 
| GSuite.DriveChange.file.capabilities.canMoveItemWithinDrive | Boolean | Whether the current user can move this item within this drive. | 
| GSuite.DriveChange.file.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of this file. | 
| GSuite.DriveChange.file.capabilities.canReadDrive | Boolean | Whether the current user can read the shared drive to which this file belongs. Only populated for items in shared drives. | 
| GSuite.DriveChange.file.capabilities.canRemoveChildren | Boolean | Whether the current user can remove children from this folder. | 
| GSuite.DriveChange.file.capabilities.canRemoveMyDriveParent | Boolean | Whether the current user can remove a parent from the item without adding another parent in the same request. Not populated for shared drive files. | 
| GSuite.DriveChange.file.capabilities.canRename | Boolean | Whether the current user can rename this file. | 
| GSuite.DriveChange.file.capabilities.canShare | Boolean | Whether the current user can modify the sharing settings for this file. | 
| GSuite.DriveChange.file.capabilities.canTrash | Boolean | Whether the current user can move this file to trash. | 
| GSuite.DriveChange.file.capabilities.canTrashChildren | Boolean | Whether the current user can trash children of this folder. This is false when the item is not a folder. Only populated for items in shared drives. | 
| GSuite.DriveChange.file.capabilities.canUntrash | Boolean | Whether the current user can restore this file from trash. | 
| GSuite.DriveChange.file.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download this file, should be disabled for readers and commenters. | 
| GSuite.DriveChange.file.writersCanShare | Boolean | Whether users with only writer permission can modify the file's permissions. Not populated for items in shared drives. | 
| GSuite.DriveChange.file.permissions.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.permissions.id | String | The ID of this permission. | 
| GSuite.DriveChange.file.permissions.type | String | The type of the grantee. | 
| GSuite.DriveChange.file.permissions.emailAddress | String | The email address of the user or group to which this permission refers. | 
| GSuite.DriveChange.file.permissions.domain | String | The domain to which this permission refers. | 
| GSuite.DriveChange.file.permissions.role | String | The role granted by this permission. | 
| GSuite.DriveChange.file.permissions.view | String | Indicates the view for this permission. | 
| GSuite.DriveChange.file.permissions.allowFileDiscovery | Boolean | Whether the permission allows the file to be discovered through search. | 
| GSuite.DriveChange.file.permissions.displayName | String | The "pretty" name of the value of the permission. | 
| GSuite.DriveChange.file.permissions.photoLink | String | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.permissions.expirationTime | Date | The time at which this permission will expire \(RFC 3339 date-time\). | 
| GSuite.DriveChange.file.permissions.permissionDetails.permissionType | String | The permission type for this user. | 
| GSuite.DriveChange.file.permissions.permissionDetails.role | String | The primary role for this user. | 
| GSuite.DriveChange.file.permissions.permissionDetails.inheritedFrom | String | The ID of the item from which this permission is inherited. | 
| GSuite.DriveChange.file.permissions.permissionDetails.inherited | Boolean | Whether this permission is inherited. | 
| GSuite.DriveChange.file.permissions.deleted | Boolean | Whether the account associated with this permission has been deleted. | 
| GSuite.DriveChange.file.permissionIds | Unknown | List of permission IDs for users with access to this file. | 
| GSuite.DriveChange.file.hasAugmentedPermissions | Boolean | Whether there are permissions directly on this file. This field is only populated for items in shared drives. | 
| GSuite.DriveChange.file.folderColorRgb | String | The color for a folder as an RGB hex string. | 
| GSuite.DriveChange.file.originalFilename | String | The original filename of the uploaded content if available, or else the original value of the name field. This is only available for files with binary content in Google Drive. | 
| GSuite.DriveChange.file.fullFileExtension | String | The full file extension extracted from the name field. | 
| GSuite.DriveChange.file.fileExtension | String | The final component of fullFileExtension. This is only available for files with binary content in Google Drive. | 
| GSuite.DriveChange.file.md5Checksum | String | The MD5 checksum for the content of the file. This is only applicable to files with binary content in Google Drive. | 
| GSuite.DriveChange.file.size | Number | The size of the file's content in bytes. This is only applicable to files with binary content in Google Drive. | 
| GSuite.DriveChange.file.quotaBytesUsed | Number | The number of storage quota bytes used by the file. This includes the head revision as well as previous revisions with keepForever enabled. | 
| GSuite.DriveChange.file.headRevisionId | String | The ID of the file's head revision. This is currently only available for files with binary content in Google Drive. | 
| GSuite.DriveChange.file.contentHints.thumbnail.image | Unknown | The thumbnail data encoded with URL-safe Base64 \(RFC 4648 section 5\). | 
| GSuite.DriveChange.file.contentHints.thumbnail.mimeType | String | The MIME type of the thumbnail. | 
| GSuite.DriveChange.file.contentHints.indexableText | String | Text to be indexed for the file to improve fullText queries. This is limited to 128KB in length and may contain HTML elements. | 
| GSuite.DriveChange.file.imageMediaMetadata.width | Number | The width of the image in pixels. | 
| GSuite.DriveChange.file.imageMediaMetadata.height | Number | The height of the image in pixels. | 
| GSuite.DriveChange.file.imageMediaMetadata.rotation | Number | The number of clockwise 90 degree rotations applied from the image's original orientation. | 
| GSuite.DriveChange.file.imageMediaMetadata.location.latitude | Number | The latitude stored in the image. | 
| GSuite.DriveChange.file.imageMediaMetadata.location.longitude | Number | The longitude stored in the image. | 
| GSuite.DriveChange.file.imageMediaMetadata.location.altitude | Number | The altitude stored in the image. | 
| GSuite.DriveChange.file.imageMediaMetadata.time | String | The date and time the photo was taken \(EXIF DateTime\). | 
| GSuite.DriveChange.file.imageMediaMetadata.cameraMake | String | The make of the camera used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.cameraModel | String | The model of the camera used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.exposureTime | Number | The length of the exposure, in seconds. | 
| GSuite.DriveChange.file.imageMediaMetadata.aperture | Number | The aperture used to create the photo \(f-number\). | 
| GSuite.DriveChange.file.imageMediaMetadata.flashUsed | Boolean | Whether a flash was used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.focalLength | Number | The focal length used to create the photo, in millimeters. | 
| GSuite.DriveChange.file.imageMediaMetadata.isoSpeed | Number | The ISO speed used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.meteringMode | String | The metering mode used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.sensor | String | The type of sensor used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.exposureMode | String | The exposure mode used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.colorSpace | String | The color space of the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.whiteBalance | String | The white balance mode used to create the photo. | 
| GSuite.DriveChange.file.imageMediaMetadata.exposureBias | Number | The exposure bias of the photo \(APEX value\). | 
| GSuite.DriveChange.file.imageMediaMetadata.maxApertureValue | Number | The smallest f-number of the lens at the focal length used to create the photo \(APEX value\). | 
| GSuite.DriveChange.file.imageMediaMetadata.subjectDistance | Number | The distance to the subject of the photo, in meters. | 
| GSuite.DriveChange.file.imageMediaMetadata.lens | String | The lens used to create the photo. | 
| GSuite.DriveChange.file.videoMediaMetadata.width | Number | The width of the video in pixels. | 
| GSuite.DriveChange.file.videoMediaMetadata.height | Number | The height of the video in pixels. | 
| GSuite.DriveChange.file.videoMediaMetadata.durationMillis | Number | The duration of the video in milliseconds. | 
| GSuite.DriveChange.file.isAppAuthorized | Boolean | Whether the file was created or opened by the requesting app. | 
| GSuite.DriveChange.file.exportLinks | Unknown | Links for exporting Google Docs to specific formats. | 
| GSuite.DriveChange.file.shortcutDetails.targetId | String | The ID of the file that this shortcut points to. | 
| GSuite.DriveChange.file.shortcutDetails.targetMimeType | String | The MIME type of the file that this shortcut points to. The value of this field is a snapshot of the target's MIME type, captured when the shortcut is created. | 
| GSuite.DriveChange.file.contentRestrictions.readOnly | Boolean | Whether the content of the file is read-only. | 
| GSuite.DriveChange.file.contentRestrictions.reason | String | Reason for why the content of the file is restricted. This is only mutable on requests that also set readOnly=true. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.displayName | String | A plain text displayable name for this user. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.photoLink | String | A link to the user's profile photo, if available. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.me | Boolean | Whether this user is the requesting user. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.permissionId | String | The user's ID as visible in Permission resources. | 
| GSuite.DriveChange.file.contentRestrictions.restrictingUser.emailAddress | String | The email address of the user. This may not be present in certain contexts if the user has not made their email address visible to the requester. | 
| GSuite.DriveChange.file.contentRestrictions.restrictionTime | Date | The time at which the content restriction was set \(formatted RFC 3339 timestamp\). Only populated if readOnly is true. | 
| GSuite.DriveChange.file.contentRestrictions.type | String | The type of the content restriction. Currently the only possible value is globalContentRestriction. | 
| GSuite.DriveChange.drive.kind | String | Identifies what kind of resource this is. | 
| GSuite.DriveChange.drive.id | String | The ID of this shared drive which is also the ID of the top level folder of this shared drive. | 
| GSuite.DriveChange.drive.name | String | The name of this shared drive. | 
| GSuite.DriveChange.drive.themeId | String | The ID of the theme from which the background image and color will be set. | 
| GSuite.DriveChange.drive.colorRgb | String | The color of this shared drive as an RGB hex string. It can only be set on a drive.drives.update request that does not set themeId. | 
| GSuite.DriveChange.drive.backgroundImageFile.id | String | The ID of an image file in Google Drive to use for the background image. | 
| GSuite.DriveChange.drive.backgroundImageFile.xCoordinate | Number | The X coordinate of the upper left corner of the cropping area in the background image. | 
| GSuite.DriveChange.drive.backgroundImageFile.yCoordinate | Number | The Y coordinate of the upper left corner of the cropping area in the background image. | 
| GSuite.DriveChange.drive.backgroundImageFile.width | Number | The width of the cropped image in the closed range of 0 to 1. | 
| GSuite.DriveChange.drive.backgroundImageLink | String | A short-lived link to this shared drive's background image. | 
| GSuite.DriveChange.drive.capabilities.canAddChildren | Boolean | Whether the current user can add children to folders in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canChangeCopyRequiresWriterPermissionRestriction | Boolean | Whether the current user can change the copyRequiresWriterPermission restriction of this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canChangeDomainUsersOnlyRestriction | Boolean | Whether the current user can change the domainUsersOnly restriction of this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canChangeDriveBackground | Boolean | Whether the current user can change the background of this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canChangeDriveMembersOnlyRestriction | Boolean | Whether the current user can change the driveMembersOnly restriction of this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canComment | Boolean | Whether the current user can comment on files in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canCopy | Boolean | Whether the current user can copy files in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canDeleteChildren | Boolean | Whether the current user can delete children from folders in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canDeleteDrive | Boolean | Whether the current user can delete this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canDownload | Boolean | Whether the current user can download files in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canEdit | Boolean | Whether the current user can edit files in this shared drive | 
| GSuite.DriveChange.drive.capabilities.canListChildren | Boolean | Whether the current user can list the children of folders in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canManageMembers | Boolean | Whether the current user can add members to this shared drive or remove them or change their role. | 
| GSuite.DriveChange.drive.capabilities.canReadRevisions | Boolean | Whether the current user can read the revisions resource of files in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canRename | Boolean | Whether the current user can rename files or folders in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canRenameDrive | Boolean | Whether the current user can rename this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canShare | Boolean | Whether the current user can share files or folders in this shared drive. | 
| GSuite.DriveChange.drive.capabilities.canTrashChildren | Boolean | Whether the current user can trash children from folders in this shared drive. | 
| GSuite.DriveChange.drive.createdTime | Date | The time at which the shared drive was created \(RFC 3339 date-time\). | 
| GSuite.DriveChange.drive.hidden | Boolean | Whether the shared drive is hidden from default view. | 
| GSuite.DriveChange.drive.restrictions.adminManagedRestrictions | Boolean | Whether administrative privileges on this shared drive are required to modify restrictions. | 
| GSuite.DriveChange.drive.restrictions.copyRequiresWriterPermission | Boolean | Whether the options to copy, print, or download files inside this shared drive, should be disabled for readers and commenters. | 
| GSuite.DriveChange.drive.restrictions.domainUsersOnly | Boolean | Whether access to this shared drive and items inside this shared drive is restricted to users of the domain to which this shared drive belongs. | 
| GSuite.DriveChange.drive.restrictions.driveMembersOnly | Boolean | Whether access to items inside this shared drive is restricted to its members. | 


#### Command Example
```!gsuite-drive-changes-list page_token=485 user_id=user@domain.com fields=advance page_size=2```

#### Context Example
```
{
    "GSuite": {
        "DriveChange": [
            {
                "changeType": "file",
                "file": {
                    "capabilities": {
                        "canAddChildren": false,
                        "canAddMyDriveParent": false,
                        "canChangeCopyRequiresWriterPermission": true,
                        "canChangeViewersCanCopyContent": true,
                        "canComment": true,
                        "canCopy": true,
                        "canDelete": true,
                        "canDownload": true,
                        "canEdit": true,
                        "canListChildren": false,
                        "canModifyContent": true,
                        "canMoveChildrenWithinDrive": false,
                        "canMoveItemIntoTeamDrive": true,
                        "canMoveItemOutOfDrive": true,
                        "canMoveItemWithinDrive": true,
                        "canReadRevisions": true,
                        "canRemoveChildren": false,
                        "canRemoveMyDriveParent": true,
                        "canRename": true,
                        "canShare": true,
                        "canTrash": true,
                        "canUntrash": true
                    },
                    "copyRequiresWriterPermission": false,
                    "createdTime": "2020-09-18T16:44:58.481Z",
                    "explicitlyTrashed": false,
                    "fileExtension": "PNG",
                    "fullFileExtension": "PNG",
                    "hasThumbnail": true,
                    "headRevisionId": "0B4EoMKFUOWuTV1VRSU1xN3ZXSU5kRHZrcWVUZ0Nha0xVQ3FVPQ",
                    "iconLink": "https://drive-thirdparty.googleusercontent.com/16/type/image/png",
                    "id": "1i_rViDYPnCJERqClTVXxgT2BlbBozvsl",
                    "imageMediaMetadata": {
                        "height": 629,
                        "rotation": 0,
                        "width": 1745
                    },
                    "isAppAuthorized": false,
                    "kind": "drive#file",
                    "lastModifyingUser": {
                        "displayName": "drive activity",
                        "emailAddress": "user@domain.com",
                        "kind": "drive#user",
                        "me": true,
                        "permissionId": "13917841530253496391"
                    },
                    "md5Checksum": "28364a0552ccfb6638d929fb31b15e18",
                    "mimeType": "image/png",
                    "modifiedByMe": true,
                    "modifiedByMeTime": "2020-08-29T05:18:45.000Z",
                    "modifiedTime": "2020-08-29T05:18:45.000Z",
                    "name": "ACL_list.PNG",
                    "originalFilename": "ACL_list.PNG",
                    "ownedByMe": true,
                    "owners": [
                        {
                            "displayName": "drive activity",
                            "emailAddress": "user@domain.com",
                            "kind": "drive#user",
                            "me": true,
                            "permissionId": "13917841530253496391"
                        }
                    ],
                    "parents": [
                        "1qczzfFtukqOKTDDNRxhJrfUxlP99DKBp"
                    ],
                    "permissionIds": [
                        "06693729183418228120",
                        "12910357923353950258k",
                        "13917841530253496391"
                    ],
                    "permissions": [
                        {
                            "deleted": false,
                            "displayName": "Deval Mehta",
                            "emailAddress": "user1@domain.com",
                            "id": "06693729183418228120",
                            "kind": "drive#permission",
                            "role": "writer",
                            "type": "user"
                        },
                        {
                            "allowFileDiscovery": false,
                            "displayName": "Data Technologies",
                            "domain": "domain.com",
                            "id": "12910357923353950258k",
                            "kind": "drive#permission",
                            "role": "reader",
                            "type": "domain"
                        },
                        {
                            "deleted": false,
                            "displayName": "drive activity",
                            "emailAddress": "user@domain.com",
                            "id": "13917841530253496391",
                            "kind": "drive#permission",
                            "role": "owner",
                            "type": "user"
                        }
                    ],
                    "quotaBytesUsed": "68787",
                    "shared": true,
                    "size": "68787",
                    "spaces": [
                        "drive"
                    ],
                    "starred": false,
                    "thumbnailLink": "https://lh3.googleusercontent.com/DTeAOSDpqZsvunN1AnZh00Rko90=s220",
                    "thumbnailVersion": "1",
                    "trashed": false,
                    "version": "2",
                    "viewedByMe": true,
                    "viewedByMeTime": "2020-09-18T16:44:58.481Z",
                    "viewersCanCopyContent": true,
                    "webContentLink": "https://drive.google.com/uc?id=123&export=download",
                    "webViewLink": "https://drive.google.com/file/d/123/view?usp=drivesdk",
                    "writersCanShare": true
                },
                "fileId": "1i_rViDYPnCJERqClTVXxgT2BlbBozvsl",
                "kind": "drive#change",
                "removed": false,
                "time": "2020-09-21T14:14:21.131Z",
                "type": "file"
            },
            {
                "changeType": "file",
                "file": {
                    "capabilities": {
                        "canAddChildren": true,
                        "canAddMyDriveParent": false,
                        "canChangeCopyRequiresWriterPermission": false,
                        "canChangeViewersCanCopyContent": false,
                        "canComment": true,
                        "canCopy": false,
                        "canDelete": true,
                        "canDownload": true,
                        "canEdit": true,
                        "canListChildren": true,
                        "canModifyContent": true,
                        "canMoveChildrenWithinDrive": true,
                        "canMoveItemIntoTeamDrive": true,
                        "canMoveItemOutOfDrive": true,
                        "canMoveItemWithinDrive": true,
                        "canReadRevisions": false,
                        "canRemoveChildren": true,
                        "canRemoveMyDriveParent": true,
                        "canRename": true,
                        "canShare": true,
                        "canTrash": true,
                        "canUntrash": true
                    },
                    "copyRequiresWriterPermission": false,
                    "createdTime": "2020-09-21T14:16:35.836Z",
                    "explicitlyTrashed": false,
                    "folderColorRgb": "#8f8f8f",
                    "hasThumbnail": false,
                    "iconLink": "https://drive-thirdparty.googleusercontent.com/16/type/application/vnd123",
                    "id": "1i8dC0MGowqwg2IjGWs1CJekqZOn5X1mb",
                    "isAppAuthorized": false,
                    "kind": "drive#file",
                    "lastModifyingUser": {
                        "displayName": "drive activity",
                        "emailAddress": "user@domain.com",
                        "kind": "drive#user",
                        "me": true,
                        "permissionId": "13917841530253496391"
                    },
                    "mimeType": "application/vnd.google-apps.folder",
                    "modifiedByMe": true,
                    "modifiedByMeTime": "2020-09-21T14:16:35.836Z",
                    "modifiedTime": "2020-09-21T14:16:35.836Z",
                    "name": "Folder_2_move",
                    "ownedByMe": true,
                    "owners": [
                        {
                            "displayName": "drive activity",
                            "emailAddress": "user@domain.com",
                            "kind": "drive#user",
                            "me": true,
                            "permissionId": "13917841530253496391"
                        }
                    ],
                    "parents": [
                        "0AIEoMKFUOWuTUk9PVA"
                    ],
                    "permissionIds": [
                        "12910357923353950258k",
                        "13917841530253496391"
                    ],
                    "permissions": [
                        {
                            "allowFileDiscovery": false,
                            "displayName": "Data Technologies",
                            "domain": "domain.com",
                            "id": "12910357923353950258k",
                            "kind": "drive#permission",
                            "role": "reader",
                            "type": "domain"
                        },
                        {
                            "deleted": false,
                            "displayName": "drive activity",
                            "emailAddress": "user@domain.com",
                            "id": "13917841530253496391",
                            "kind": "drive#permission",
                            "role": "owner",
                            "type": "user"
                        }
                    ],
                    "quotaBytesUsed": "0",
                    "shared": true,
                    "spaces": [
                        "drive"
                    ],
                    "starred": false,
                    "thumbnailVersion": "0",
                    "trashed": false,
                    "version": "2",
                    "viewedByMe": true,
                    "viewedByMeTime": "2020-09-21T14:16:35.836Z",
                    "viewersCanCopyContent": true,
                    "webViewLink": "https://drive.google.com/drive/folders/123",
                    "writersCanShare": true
                },
                "fileId": "1i8dC0MGowqwg2IjGWs1CJekqZOn5X1mb",
                "kind": "drive#change",
                "removed": false,
                "time": "2020-09-21T14:16:36.333Z",
                "type": "file"
            }
        ],
        "PageToken": {
            "DriveChange": {
                "nextPageToken": "489",
                "userId": "user@domain.com"
            }
        }
    }
}
```

#### Human Readable Output

>### Next Page Token: 489
>### Files(s)
>|Id|Name|Size ( Bytes )|Modified Time|Last Modifying User|
>|---|---|---|---|---|
>| 1i_rViDYPnCJERqClTVXxgT2BlbBozvsl | ACL_list.PNG | 68787 | 2020-08-29T05:18:45.000Z | drive activity |
>| 1i8dC0MGowqwg2IjGWs1CJekqZOn5X1mb | Folder_2_move |  | 2020-09-21T14:16:35.836Z | drive activity |
>### Drive(s)
>**No entries.**


### gsuite-drive-activity-list
***
Query past activity in Google Drive.


#### Base Command

`gsuite-drive-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user's primary email address. | Optional | 
| ancestor_name | Return activities for this Drive folder and all children and descendants. The format is "items/ITEM_ID". | Optional | 
| item_name | Return activities for this Drive item. The format is "items/ITEM_ID". | Optional | 
| filter | The filtering for items returned from this query request. The format of the filter string is a sequence of expressions, joined by an optional "AND\", where each expression is of the form "field operator value".<br/><br/>Supported fields:<br/>time - Uses numerical operators on date values either in terms of milliseconds since Jan 1, 1970 or in RFC 3339 format.<br/>Examples:<br/>time &gt; 1452409200000 AND time &lt;= 1492812924310<br/>time &gt;= "2016-01-10T01:02:03-05:00"<br/><br/>detail.action_detail_case - Uses the "has" operator (:) and either a singular value or a list of allowed action types enclosed in parentheses.<br/>Examples:<br/>detail.action_detail_case: RENAME<br/>detail.action_detail_case:(CREATE EDIT)<br/>-detail.action_detail_case:MOVE" | Optional | 
| time_range | The time range to consider for getting drive activity. Use the format "&lt;number&gt; &lt;time unit&gt;". <br/>Example: 12 hours, 7 days, 3 months, 1 year. This argument will override if the filter argument is given. | Optional | 
| action_detail_case_include | A singular value or a list of allowed action types enclosed in parentheses. Which filters based on given actions. Examples: <br/>RENAME <br/>(CREATE EDIT)<br/>This argument will override if the filter argument is given. | Optional | 
| action_detail_case_remove | A singular value or a list of allowed action types enclosed in parentheses. Which filters based on given actions Examples:<br/>RENAME <br/>(CREATE EDIT)<br/>This argument will override if the filter argument is given. | Optional | 
| page_token | The token identifying which page of results to return. Set this to the nextPageToken value returned from a previous query to obtain the following page of results. If not set, the first page of results will be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.PageToken.DriveActivity.nextPageToken | String | Token to retrieve the next page of results, or empty if there are no more results in the list. | 
| GSuite.DriveActivity.primaryActionDetail.create.new | Boolean | If true, the object was newly created. | 
| GSuite.DriveActivity.primaryActionDetail.create.upload | Boolean | If true, the object originated externally and was uploaded to Drive. | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.primaryActionDetail.create.copy.originalObject.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.primaryActionDetail.edit | Boolean | If true, the object was edited. | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.driveItem.driveFolder.type | String | The type of a Drive folder. | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.primaryActionDetail.move.addedParents.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.primaryActionDetail.move.removedParents.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.primaryActionDetail.rename.oldTitle | String | The previous title of the drive object. | 
| GSuite.DriveActivity.primaryActionDetail.rename.newTitle | String | The new title of the drive object. | 
| GSuite.DriveActivity.primaryActionDetail.delete.type | String | The type of delete action taken. | 
| GSuite.DriveActivity.primaryActionDetail.restore.type | String | The type of restore action taken. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g. in the user's "Shared with me" collection\) without needing a link to the item. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.group.email | String | The email address of the group. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.group.title | String | The title of the group. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.addedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g. in the user's "Shared with me" collection\) without needing a link to the item. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.group.email | String | The email address of the group. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.group.title | String | The title of the group. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.primaryActionDetail.permissionChange.removedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GSuite.DriveActivity.primaryActionDetail.comment.mentionedUsers.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.primaryActionDetail.comment.mentionedUsers.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.primaryActionDetail.comment.mentionedUsers.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.primaryActionDetail.comment.mentionedUsers.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.primaryActionDetail.comment.post.subtype | String | The sub-type of post event. | 
| GSuite.DriveActivity.primaryActionDetail.comment.assignment.subtype | String | The sub-type of assignment event. | 
| GSuite.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.primaryActionDetail.comment.assignment.assignedUser.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.primaryActionDetail.comment.suggestion.subtype | String | The sub-type of suggestion event. | 
| GSuite.DriveActivity.primaryActionDetail.dlpChange.type | String | The type of Data Leak Prevention \(DLP\) change. | 
| GSuite.DriveActivity.primaryActionDetail.reference.type | String | The reference type corresponding to this event. | 
| GSuite.DriveActivity.primaryActionDetail.settingsChange.restrictionChanges.feature | String | The feature which had a change in restriction policy. | 
| GSuite.DriveActivity.primaryActionDetail.settingsChange.restrictionChanges.newRestriction | String | The restriction in place after the change. | 
| GSuite.DriveActivity.actors.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actors.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actors.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actors.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actors.anonymous | Boolean | If true, the user is an anonymous user. | 
| GSuite.DriveActivity.actors.impersonation.impersonatedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actors.impersonation.impersonatedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actors.impersonation.impersonatedUser.deletedUser | Boolean | If true, A user whose account has since been deleted. | 
| GSuite.DriveActivity.actors.impersonation.impersonatedUser.unknownUser | Boolean | If true, A user about whom nothing is currently known. | 
| GSuite.DriveActivity.actors.system.type | String | The type of the system event that may triggered activity. | 
| GSuite.DriveActivity.actors.administrator | Boolean | If true, the user is an administrator. | 
| GSuite.DriveActivity.actions.detail.create.new | Boolean | If true, the object was newly created. | 
| GSuite.DriveActivity.actions.detail.create.upload | Boolean | If true, the object originated externally and was uploaded to Drive. | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.detail.create.copy.originalObject.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.detail.edit | Boolean | If true, the object was edited. | 
| GSuite.DriveActivity.actions.detail.move.addedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.detail.move.addedParents.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.detail.move.addedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.detail.move.addedParents.driveItem.driveFolder.type | String | The type of a Drive folder. | 
| GSuite.DriveActivity.actions.detail.move.addedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.detail.move.addedParents.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.detail.move.removedParents.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.detail.move.removedParents.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.detail.move.removedParents.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.detail.move.removedParents.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.actions.detail.move.removedParents.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.detail.move.removedParents.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.detail.rename.oldTitle | String | The previous title of the drive object. | 
| GSuite.DriveActivity.actions.detail.rename.newTitle | String | The new title of the drive object. | 
| GSuite.DriveActivity.actions.detail.delete.type | String | The type of delete action taken. | 
| GSuite.DriveActivity.actions.detail.restore.type | String | The type of restore action taken. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g. in the user's "Shared with me" collection\) without needing a link to the item. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.group.email | String | The email address of the group. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.group.title | String | The title of the group. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.actions.detail.permissionChange.addedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.role | String | Indicates the Google Drive permissions role. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.allowDiscovery | Boolean | If true, the item can be discovered \(e.g. in the user's "Shared with me" collection\) without needing a link to the item. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.group.email | String | The email address of the group. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.group.title | String | The title of the group. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.actions.detail.permissionChange.removedPermissions.anyone | Boolean | If true, represents any user \(including a logged out user\). | 
| GSuite.DriveActivity.actions.detail.comment.mentionedUsers.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.detail.comment.mentionedUsers.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.detail.comment.mentionedUsers.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.detail.comment.mentionedUsers.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.detail.comment.post.subtype | String | The sub-type of post event. | 
| GSuite.DriveActivity.actions.detail.comment.assignment.subtype | String | The sub-type of assignment event. | 
| GSuite.DriveActivity.actions.detail.comment.assignment.assignedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.detail.comment.assignment.assignedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.detail.comment.assignment.assignedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.detail.comment.assignment.assignedUser.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.detail.comment.suggestion.subtype | String | The sub-type of suggestion event. | 
| GSuite.DriveActivity.actions.detail.dlpChange.type | String | The type of Data Leak Prevention \(DLP\) change. | 
| GSuite.DriveActivity.actions.detail.reference.type | String | The reference type corresponding to this event. | 
| GSuite.DriveActivity.actions.detail.settingsChange.restrictionChanges.feature | String | The feature which had a change in restriction policy. | 
| GSuite.DriveActivity.actions.detail.settingsChange.restrictionChanges.newRestriction | String | The restriction in place after the change. | 
| GSuite.DriveActivity.actions.actor.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.actor.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.actor.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.actor.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.actor.anonymous | Boolean | If true, the user is an anonymous user. | 
| GSuite.DriveActivity.actions.actor.impersonation.impersonatedUser.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.actor.impersonation.impersonatedUser.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.actor.impersonation.impersonatedUser.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.actor.impersonation.impersonatedUser.unknownUser | String | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.actor.system.type | String | The type of the system event that may triggered activity. | 
| GSuite.DriveActivity.actions.actor.administrator | Boolean | If true, the user is an administrator. | 
| GSuite.DriveActivity.actions.target.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.target.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.target.driveItem.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.actions.target.driveItem.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.actions.target.driveItem.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.actions.target.driveItem.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.target.driveItem.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.target.driveItem.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.target.driveItem.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.target.driveItem.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.target.driveItem.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.target.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.target.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.actions.target.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.target.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.target.drive.root.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.target.drive.root.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.target.drive.root.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.actions.target.drive.root.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.actions.target.drive.root.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.actions.target.drive.root.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.target.drive.root.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.target.drive.root.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.target.drive.root.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.target.drive.root.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.target.drive.root.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.target.drive.root.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.target.drive.root.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.actions.target.fileComment.legacyCommentId | String | The comment in the discussion thread. | 
| GSuite.DriveActivity.actions.target.fileComment.legacyDiscussionId | String | The discussion thread to which the comment was added. | 
| GSuite.DriveActivity.actions.target.fileComment.linkToDiscussion | String | The link to the discussion thread containing this comment, for example, "https://docs.google.com/DOCUMENT_ID/edit?disco=THREAD_ID". | 
| GSuite.DriveActivity.actions.target.fileComment.parent.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.actions.target.fileComment.parent.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.actions.target.fileComment.parent.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.actions.target.fileComment.parent.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.actions.timestamp | String | The activity occurred at this specific time. | 
| GSuite.DriveActivity.actions.timeRange.startTime | String | The start of the time range. | 
| GSuite.DriveActivity.actions.timeRange.endTime | String | The end of the time range. | 
| GSuite.DriveActivity.targets.driveItem.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.targets.driveItem.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.targets.driveItem.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.targets.driveItem.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.targets.driveItem.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.targets.driveItem.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.targets.driveItem.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.targets.driveItem.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.targets.driveItem.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.targets.driveItem.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.targets.driveItem.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.targets.driveItem.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.targets.driveItem.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.targets.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.targets.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.targets.drive.root.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.targets.drive.root.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.targets.drive.root.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.targets.drive.root.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.targets.drive.root.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.targets.drive.root.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.targets.drive.root.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.targets.drive.root.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.targets.drive.root.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.targets.drive.root.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.targets.drive.root.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.targets.drive.root.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.targets.drive.root.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.targets.fileComment.legacyCommentId | String | The comment in the discussion thread. | 
| GSuite.DriveActivity.targets.fileComment.legacyDiscussionId | String | The discussion thread to which the comment was added. | 
| GSuite.DriveActivity.targets.fileComment.linkToDiscussion | String | The link to the discussion thread containing this comment, for example, "https://docs.google.com/DOCUMENT_ID/edit?disco=THREAD_ID". | 
| GSuite.DriveActivity.targets.fileComment.parent.name | String | The target Drive item. The format is "items/ITEM_ID". | 
| GSuite.DriveActivity.targets.fileComment.parent.title | String | The title of the Drive item. | 
| GSuite.DriveActivity.targets.fileComment.parent.mimeType | String | The MIME type of the Drive item. | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.domain.name | String | The name of the domain, e.g. "google.com". | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.domain.legacyId | String | An opaque string used to identify this domain. | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.user.knownUser.personName | String | The identifier for this user that can be used with the People API to get more information. The format is "people/ACCOUNT_ID". | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.user.knownUser.isCurrentUser | Boolean | True if this is the user making the request. | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.user.deletedUser | Boolean | If true, a user whose account has since been deleted. | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.user.unknownUser | Boolean | If true, a user about whom nothing is currently known. | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.drive.name | String | The resource name of the shared drive. The format is "COLLECTION_ID/DRIVE_ID". | 
| GSuite.DriveActivity.targets.fileComment.parent.owner.drive.title | String | The title of the shared drive. | 
| GSuite.DriveActivity.targets.fileComment.parent.driveFile | Boolean | If true, the Drive item is a file. | 
| GSuite.DriveActivity.targets.fileComment.parent.driveFolder.type | String | The type of Drive folder. | 
| GSuite.DriveActivity.timestamp | String | The activity occurred at this specific time. | 
| GSuite.DriveActivity.timeRange.startTime | String | The start of the time range. | 
| GSuite.DriveActivity.timeRange.endTime | String | The end of the time range. | 


#### Command Example
```!gsuite-drive-activity-list user_id=user@domain.com time_range="55 minutes"```

#### Context Example
```
{
    "GSuite": {
        "DriveActivity": [
            {
                "actions": [
                    {
                        "detail": {
                            "permissionChange": {
                                "addedPermissions": [
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/112596790873"
                                            }
                                        }
                                    },
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/113493660192005193453"
                                            }
                                        }
                                    },
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/101124359955557659537"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ],
                "actors": [
                    {
                        "user": {
                            "knownUser": {
                                "isCurrentUser": true,
                                "personName": "people/119443780932332"
                            }
                        }
                    }
                ],
                "primaryActionDetail": {
                    "permissionChange": {
                        "addedPermissions": [
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/112596790873"
                                    }
                                }
                            },
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/113493660192005193453"
                                    }
                                }
                            },
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/101124359955557659537"
                                    }
                                }
                            }
                        ]
                    }
                },
                "targets": [
                    {
                        "driveItem": {
                            "driveFile": true,
                            "file": true,
                            "mimeType": "image/png",
                            "name": "items/1i_rViDYPnCJERqClTVXxgT2BlbBozvsl",
                            "owner": {
                                "domain": {
                                    "legacyId": "119443780932332",
                                    "name": "domain.com"
                                },
                                "user": {
                                    "knownUser": {
                                        "isCurrentUser": true,
                                        "personName": "people/119443780932332"
                                    }
                                }
                            },
                            "title": "ACL_list.PNG"
                        }
                    }
                ],
                "timestamp": "2020-09-25T12:31:07.105Z"
            },
            {
                "actions": [
                    {
                        "detail": {
                            "permissionChange": {
                                "addedPermissions": [
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/112596790873"
                                            }
                                        }
                                    },
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/113493660192005193453"
                                            }
                                        }
                                    },
                                    {
                                        "role": "EDITOR",
                                        "user": {
                                            "knownUser": {
                                                "personName": "people/101124359955557659537"
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                ],
                "actors": [
                    {
                        "user": {
                            "knownUser": {
                                "isCurrentUser": true,
                                "personName": "people/119443780932332"
                            }
                        }
                    }
                ],
                "primaryActionDetail": {
                    "permissionChange": {
                        "addedPermissions": [
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/112596790873"
                                    }
                                }
                            },
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/113493660192005193453"
                                    }
                                }
                            },
                            {
                                "role": "EDITOR",
                                "user": {
                                    "knownUser": {
                                        "personName": "people/101124359955557659537"
                                    }
                                }
                            }
                        ]
                    }
                },
                "targets": [
                    {
                        "driveItem": {
                            "driveFolder": {
                                "type": "STANDARD_FOLDER"
                            },
                            "folder": {
                                "type": "STANDARD_FOLDER"
                            },
                            "mimeType": "application/vnd.google-apps.folder",
                            "name": "items/1qczzfFtukqOKTDDNRxhJrfUxlP99DKBp",
                            "owner": {
                                "domain": {
                                    "legacyId": "119443780932332",
                                    "name": "domain.com"
                                },
                                "user": {
                                    "knownUser": {
                                        "isCurrentUser": true,
                                        "personName": "people/119443780932332"
                                    }
                                }
                            },
                            "title": "teste move"
                        }
                    }
                ],
                "timestamp": "2020-09-25T12:31:05.464Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### PermissionChange Activity
>|Activity Time|Added Permissions|
>|---|---|
>| 2020-09-25T12:31:07.105Z | Role: EDITOR<br/>Person Name: people/112596790873<br/>Role: EDITOR<br/>Person Name: people/113493660192005193453<br/>Role: EDITOR<br/>Person Name: people/101124359955557659537<br/> |
>| 2020-09-25T12:31:05.464Z | Role: EDITOR<br/>Person Name: people/112596790873<br/>Role: EDITOR<br/>Person Name: people/113493660192005193453<br/>Role: EDITOR<br/>Person Name: people/101124359955557659537<br/> |
