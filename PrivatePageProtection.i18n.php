<?php
/**
 * Internationalisation for PrivatePageProtection extension
 *
 * @file
 * @ingroup Extensions
 */

$messages = array();

/** English
 * @author Daniel Kinzler
 */
$messages['en'] = array(
	'privatepp-desc' => 'Allows restricting page access based on user group',
	
	'privatepp-lockout-prevented' => 'Lockout prevented: You have tried to restrict access to this page to {{PLURAL:$2|the group|one of the groups}} $1. 
Since you are not a member of {{PLURAL:$2|this group|any of these groups}}, you would not be able to access the page after saving it. 
Saving was aborted to avoid this.',
);

/** Message documentation (Message documentation)
 * @author Daniel Kinzler
 */
$messages['qqq'] = array(
	'privatepp-desc' => '{{desc}}',
);

/** German (Deutsch)
 * @author Daniel Kinzler
 * @author Kghbln
 */
$messages['de'] = array(
	'privatepp-desc' => 'Ermöglicht das Beschränken das Zugangs zu Wikiseiten auf Basis von Benutzergruppen',
	'privatepp-lockout-prevented' => 'Die Aussperrung wurde verhindert: Du hast versucht, den Zugang zu dieser Seite auf {{PLURAL:$2|die Benutzergruppe|die Benutzergruppen}} $1 zu beschränken. 
Da du kein Mitglied {{PLURAL:$2|dieser Benutzergruppe|einer dieser Benutzergruppen}} bist, könntest du nach dem Speichern nicht mehr auf die Seite zugreifen. 
Um dies zu vermeiden, wurde das Speichern abgebrochen.',
);

/** German (formal address) (‪Deutsch (Sie-Form)‬)
 * @author Daniel Kinzler
 * @author Kghbln
 */
$messages['de-formal'] = array(
	'privatepp-lockout-prevented' => 'Die Aussperrung wurde verhindert: Sie haben versucht, den Zugang zu dieser Seite auf {{PLURAL:$2|die Benutzergruppe|die Benutzergruppen}} $1 zu beschränken. 
Da Sie kein Mitglied {{PLURAL:$2|dieser Benutzergruppe|einer dieser Benutzergruppen}} sind, könnten Sie nach dem Speichern nicht mehr auf die Seite zugreifen. 
Um dies zu vermeiden, wurde das Speichern abgebrochen.',
);

