<?php
/**
 * PrivatePageProtection extension - implements per-page acccess restrictions based on user group.
 * Which groups are authorized for viewing is defined on-page, using a parser function.
 *
 * @file
 * @ingroup Extensions
 * @author Daniel Kinzler, brightbyte.de
 * @copyright © 2007 Daniel Kinzler
 * @license GPL-2.0-or-later
 */

use MediaWiki\MediaWikiServices;

/*
 * WARNING: you can use this extension to deny read access to some pages. Keep in mind that this
 * may be circumvented in several ways. This extension doesn't try to
 * plug such holes. Also note that pages that are not readable will still be shown in listings,
 * such as the search page, categories, etc.
 *
 * Known ways to access "hidden" pages:
 * - transcluding as template. can be avoided using $wgNonincludableNamespaces.
 * Some search messages may reveal the page existance by producing links to it (MediaWiki:searchsubtitle,
 * MediaWiki:noexactmatch, MediaWiki:searchmenu-exists, MediaWiki:searchmenu-new...).
 *
 * NOTE: you cannot GRANT access to things forbidden by $wgGroupPermissions. You can only DENY access
 * granted there.
 */

class PrivatePageProtection {

	/**
	 * Tell MediaWiki that the parser function exists.
	 *
	 * @param Parser &$parser
	 */
	public static function onParserFirstCallInit( Parser &$parser ) {
		// Create a function hook associating the magic word
		$parser->setFunctionHook( 'allow-groups', [ __CLASS__, 'renderTag' ] );
	}

	/**
	 * Render the output of the parser function.
	 * Literally the callback for onParserFirstCallInit() above.
	 *
	 * @param Parser $parser
	 * @param string $param1
	 * @param string $param2
	 * @return array|bool
	 */
	public static function renderTag( $parser, $param1 = '', $param2 = '' ) {
		$args = func_get_args();

		if ( count( $args ) <= 1 ) {
			return true;
		}

		$groups = [];

		for ( $i = 1; $i < count( $args ); $i++ ) {
			$groups[] = strtolower( trim( $args[$i] ) ); # XXX: allow localized group names?!
		}

		$groups = implode( '|', $groups );

		$out = $parser->getOutput();

		$ppp = $out->getPageProperty( 'ppp_allowed_groups' );
		if ( $ppp ) {
			$groups = $ppp . '|' . $groups;
		}

		$out->setPageProperty( 'ppp_allowed_groups', $groups );

		return [
			'text' => '',
			'ishtml' => true,
			'inline' => true
		];
	}

	/**
	 * Returns a list of allowed groups for the given page.
	 *
	 * @param Title $title
	 * @return array
	 */
	public static function getAllowedGroups( Title $title ) {
		$result = [];
		$id = $title->getArticleID();

		if ( $id == 0 ) {
			return [];
		}

		$dbr = wfGetDB( DB_REPLICA );
		$res = $dbr->select(
			[ 'page_props' ],
			[ 'pp_value' ],
			[ 'pp_page' => $id, 'pp_propname' => 'ppp_allowed_groups' ],
			__METHOD__
		);

		if ( $res !== false ) {
			foreach ( $res as $row ) {
				$result[] = $row->pp_value;
			}
		}

		# TODO: use object cache?! get from parser cache?!
		return $result;
	}

	/**
	 * @param array|bool|string|null $groups
	 * @param User $user
	 * @return null|array Array containing error message and its params in case of error, null on success
	 */
	public static function getAccessError( $groups, User $user ) {
		if ( !$groups ) {
			return null;
		}

		if ( is_string( $groups ) ) {
			$groups = explode( '|', $groups );
		}

		$ugroups = MediaWikiServices::getInstance()
			->getUserGroupManager()
			->getUserEffectiveGroups( $user, User::READ_NORMAL, true /* avoid cache */ );

		$match = array_intersect( $ugroups, $groups );

		if ( $match ) {
			# group is allowed - keep processing
			return null;
		} else {
			# group is denied - abort
			$lang = RequestContext::getMain()->getLanguage();
			$groupLinks = [];
			if ( is_array( $groups ) ) {
				foreach ( $groups as $group ) {
					$groupLinks[] = $lang->getGroupName( $group );
				}
			}

			$err = [
				'badaccess-groups',
				$lang->commaList( $groupLinks ),
				count( $groups )
			];

			return $err;
		}
	}

	/**
	 * @param Title $title
	 * @param User $user
	 * @param string $action
	 * @param mixed &$result
	 * @return bool
	 */
	public static function ongetUserPermissionsErrorsExpensive( $title, $user, $action, &$result ) {
		$groups = self::getAllowedGroups( $title );
		$result = self::getAccessError( $groups, $user );

		if ( !$result ) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Prevent users from saving a page with access restrictions that
	 * would lock them out of the page.
	 *
	 * @param MediaWiki\Revision\RenderedRevision $renderedRevision
	 * @param MediaWiki\User\UserIdentity $user
	 * @param CommentStoreComment $summary
	 * @param int $flags
	 * @param Status $hookStatus
	 * @return bool
	 */
	public static function onMultiContentSave(
		MediaWiki\Revision\RenderedRevision $renderedRevision,
		MediaWiki\User\UserIdentity $user,
		CommentStoreComment $summary,
		$flags,
		Status $hookStatus
	) {
		$user = User::newFromIdentity( $user );

		$groups = $renderedRevision->getRevisionParserOutput()->getPageProperty( 'ppp_allowed_groups' );

		$err = self::getAccessError( $groups, $user );
		if ( !$err ) {
			return true;
		}

		$err[0] = 'privatepp-lockout-prevented'; # override message key

		$hookStatus->fatal( $err[0], $err[1], $err[2] ); # message, groups, count

		return false;
	}

}
