/**
 * This module assumes:
 *      1. You have the wordpress_logged_in_[hash] cookie
 *      2. You have a connection to your Wordpress instance's SQL database,
 *         Specifically the wp_users & wp_metadata tables
 */

import { WordpressAuth } from "./wordpressAuth";

const wpLoggedInKey = '';
const wpLoggedInSalt = '';
const wpLoggedInCookieString = "";

// Step 0: Create the interface to the WP instance
const wordpressAuth = WordpressAuth.create(wpLoggedInKey, wpLoggedInSalt);
// OR => new WordpressAuth(wpLoggedInKey, wpLoggedInSalt);

// Step 1: Parse the wordpress_logged_in_[hash] cookie
const cookie = wordpressAuth.parseCookie(wpLoggedInCookieString);

// Step 2: Get the username from the cookie
const user = getUserByName(cookie.getUsername());

// Step 3: (Implemented by you!) Get the user's WP ID, passed_hash from the [prefix]_users table, 
// and get the meta_value of the session_token in 

// Step 4: Authenticate the cookie
if(cookie.authenticate(user.userId, user.hashedPass, user.sessionToken)){
    // User is authenticated - access granted!
}
else{
    // Reject call - HTTP 401
}