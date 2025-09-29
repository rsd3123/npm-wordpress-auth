/**
 * Test that valid cookies are authenticated & that invalid cookies are rejected for the correct reason.
 * 
 *      To get session token for user: 
 *          SELECT meta_value FROM [prefix]_usermeta WHERE meta_key='session_tokens' AND user_id=[id];
 *
 *      Cookie Format:
 *          [name]|[expiration]|[token]|[hmac]|[scheme (optional)]
 *          admin|1759268598|eQYPL2FQgvhfhg1KWfSec5i8uamz9G3tulyEhtRd5IK|7484333b183bb4de0f3341c940b645d1685dadb0b0fc6dff4b7f90fba17c7216
 * 
 *      Session Token Format:
 *          a:1:{s:64:"f525ea74187a34d8e2dd738658a5159143cae239b447d924ae63dde07fe383a8";a:4:{s:10:"expiration";i:1759268598;s:2:"ip";s:12:"192.168.1.18";s:2:"ua";s:125:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";s:5:"login";i:1759095798;}}
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { WordpressAuth } from "./wordpress-auth.js";

// Create mock cookie & session token
const wpAuthenticator = WordpressAuth.create(
    '^PJZ#2$.4-P&QdEEO5hl=M^[=FUE?/>g1lmXN[=?t]&|LmlfTs4`CtQ1G%G_bMw~', 
    'r2X0Mdat,jOlbXXY8vpS,~LA;[_cVXrdBb4BKkw`)Z@Bv)y@w8y;0s-EC7goygAM'
);
const exp = parseInt(Date.now()/1000 + 50000);
const cookieToken = 'eQYPL2FQgvhfhg1KWfSec5i8uamz9G3tulyEhtRd5IK';

// Create cookie hash & session token
const key = WordpressAuth.calculateHMAC(
    'md5', 
    wpAuthenticator.wpSalt,
    `admin|yzCO|${exp}|${cookieToken}`
);
// Create hash - hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );
const hash = WordpressAuth.calculateHMAC(
    'sha256', 
    key, 
    `admin|${exp}|${cookieToken}`
);
const sessionToken = WordpressAuth.hashToken(cookieToken);

/*** TESTS ***/
test('this should authenticate user', ()=>{
    const cookieString = `admin|${exp}|eQYPL2FQgvhfhg1KWfSec5i8uamz9G3tulyEhtRd5IK|${hash}`;
    const cookie = wpAuthenticator.parseCookie(cookieString);

    // Mock call to Wordpress
    const user = getWordpressUser(cookie.getUsername()); // or cookie.username
     
    // User should be authenticated
    assert.strictEqual(
        cookie.authenticate(user.id, user.hashedPass, user.sessionToken), 
        true
    );
});

test('this should not authenticate user', ()=>{

    const cookieString = `admin|${exp}|eQYPL2FQgvhfhg1KWfSec5i8uamz9G3tulyEhtRd5IK|7484334b183bb4de0f3341c940b645d1685dadb0b0fc6dff4b7f90fba17c7216`;
    const cookie = wpAuthenticator.parseCookie(cookieString);
    
    // Mock call to Wordpress
    const user = getWordpressUser(cookie.getUsername()); // or cookie.username
     
    // User should not be authnticated
    assert.strictEqual(
        cookie.authenticate(user.id, user.hashedPass, user.sessionToken), 
        false
    );
});

/**
 * Create mock user data
 */
function getWordpressUser(username){
    return {
        id:1, 
        hashedPass:'$wp$2y$10$xPWX5VOfb5SDzqKxxf9aj.JLBXEkl.UC7xYE.Xb.BjEP9zv3DyzCO', 
        sessionToken:`a:1:{s:64:"${sessionToken}";a:4:{s:10:"expiration";i:${exp};s:2:"ip";s:12:"192.168.1.18";s:2:"ua";s:125:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";s:5:"login";i:1759095798;}}`
    };
}

