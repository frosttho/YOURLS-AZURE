<?php
/*
Plugin Name: Azure OIDC
Plugin URI: https://github.com/joshp23/YOURLS-OIDC
Description: Enables OpenID Connect user authentication with Azure Active Directory
Version: 0.3.2
Author: Josh Panter, Thomas Frost
Author URI: https://ksg-media.de
*/
// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();
if( !defined( 'OIDC_BYPASS_YOURLS_AUTH' ) ) 
	define( 'OIDC_BYPASS_YOURLS_AUTH', false );
	
require_once __DIR__.'/vendor/autoload.php';
require_once (dirname(__FILE__) . '/../../../../simplesamlphp/lib/_autoload.php');

global $as;
global $attributes;
$as = new SimpleSAML_Auth_Simple('azuread');

yourls_add_filter( 'is_valid_user', 'oidc_auth' );
function oidc_auth( $valid ) {
	// check for correct context
	if ( !yourls_is_API() && !$valid ) {
		global $as;
		global $attributes;
		
		$as->requireAuth();
		$attributes = $as->getAttributes();
		
		if ( OIDC_BYPASS_YOURLS_AUTH ) {
			$user = $attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"][0];
			if ( $user ) {
				yourls_set_user($user);
				$valid = true;
			}
		} else {
			$id = $attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"][0];
			if ( $id ) {
				global $oidc_profiles;
				foreach( $oidc_profiles as $user => $hash) {
					if( $id == $hash ) {
						yourls_set_user($user);
						$valid = true;
					}
				}
			}
		}
	}
	return $valid;
}

/**
yourls_add_action( 'logout', 'oidc_logout' );
function oidc_logout() {
	yourls_store_cookie( null );
	global $as;
	$as->getLogoutURL();
}
*/

yourls_add_action( 'logoutlink', 'oidc_logout_menu' );
function oidc_logout_menu() {
	
	global $as;
	
	if( defined( 'YOURLS_USER' ) ) {
		$logout_link = yourls_apply_filter( 'logout_link', sprintf( yourls__('Hello <strong>%s</strong>'), YOURLS_USER ) . ' (<a href="' . yourls_admin_url( 'index.php' ) . '?action=logout" title="' . yourls_esc_attr__( 'Logout' ) . '">' . yourls__( 'Logout locally from YOURLS' ) . '</a>)' . ' (<a href="' . $as->getLogoutURL() . '" title="' . yourls_esc_attr__( 'Logout' ) . '">' . yourls__( 'Logout from OpenID Connect' ) . '</a>)' );
	} else {
		$logout_link = yourls_apply_filter( 'logout_link', '' );
	}
	
	echo '<li id="admin_menu_logout_link">' . $logout_link .'</li>';
	
	
}




// Largely unchanged: only checking auth against w/ cookies.
yourls_add_filter( 'shunt_check_IP_flood', 'oidc_check_ip_flood' );
function oidc_check_ip_flood ( $ip ) {
	// don't touch API logic
	if ( yourls_is_API() ) return false;
	
	yourls_do_action( 'pre_check_ip_flood', $ip ); // at this point $ip can be '', check it if your plugin hooks in here

	// Raise white flag if installing or if no flood delay defined
	if(
		( defined('YOURLS_FLOOD_DELAY_SECONDS') && YOURLS_FLOOD_DELAY_SECONDS === 0 ) ||
		!defined('YOURLS_FLOOD_DELAY_SECONDS') ||
		yourls_is_installing()
	)
		return true;

	// Don't throttle logged in users XXX and don't trigger OIDC login!
	if( yourls_is_private() && isset( $_COOKIE[ yourls_cookie_name() ] ) && yourls_check_auth_cookie() ) {
		yourls_store_cookie( YOURLS_USER );
		return true;
	}

	// Don't throttle whitelist IPs
	if( defined( 'YOURLS_FLOOD_IP_WHITELIST' ) && YOURLS_FLOOD_IP_WHITELIST ) {
		$whitelist_ips = explode( ',', YOURLS_FLOOD_IP_WHITELIST );
		foreach( (array)$whitelist_ips as $whitelist_ip ) {
			$whitelist_ip = trim( $whitelist_ip );
			if ( $whitelist_ip == $ip )
				return true;
		}
	}

	$ip = ( $ip ? yourls_sanitize_ip( $ip ) : yourls_get_IP() );

	yourls_do_action( 'check_ip_flood', $ip );

	global $ydb;
	$table = YOURLS_DB_TABLE_URL;

	$lasttime = $ydb->fetchValue( "SELECT `timestamp` FROM $table WHERE `ip` = :ip ORDER BY `timestamp` DESC LIMIT 1", array('ip' => $ip) );
	if( $lasttime ) {
		$now = date( 'U' );
		$then = date( 'U', strtotime( $lasttime ) );
		if( ( $now - $then ) <= YOURLS_FLOOD_DELAY_SECONDS ) {
			// Flood!
			yourls_do_action( 'ip_flood', $ip, $now - $then );
			yourls_die( yourls__( 'Too many URLs added too fast. Slow down please.' ), yourls__( 'Too Many Requests' ), 429 );
		}
	}

	return true;
}

?>