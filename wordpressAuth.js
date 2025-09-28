/**
 * 
 * Author: Rudy DeSanti
 * Authorize your endpoints using Wordpress
 */
import crypto from 'crypto';

export class WordpressAuth{

    /**
     * Interface to a Wordpress instance
     * @param {String} wpLoggedInKey 
     * @param {String} wpLoggedInSalt 
     */
    constructor(wpLoggedInKey, wpLoggedInSalt){
        if(!wpLoggedInKey || typeof wpLoggedInKey !== 'string')
            throw new TypeError('Invalid WP logged in key');
        else if(!wpLoggedInSalt || typeof wpLoggedInSalt !== 'string')
            throw new TypeError('Invalid WP logged in salt');

        this.wpSalt = wpLoggedInKey + wpLoggedInSalt;
    }

    static create(wpLoggedInKey, wpLoggedInSalt){
        return new WordpressAuth(wpLoggedInKey, wpLoggedInSalt);
    }

    /**
     * Parse the wordpress_logged_in_[hash] cookie
     * @param {String} loggedInCookie 
     * @returns {WordpressLoggedInCookie}
     */
    static parseCookie(loggedInCookie){
        return new WordpressLoggedInCookie(loggedInCookie, this.wpSalt);
    }

    // Crypto
    static calculateHMAC(algorithm, key, message, encoding = 'hex') {
        const hmac = crypto.createHmac(algorithm, key);
        hmac.update(message);
        return hmac.digest(encoding);
    }
    static hashToken(token){
        return crypto.createHash('sha256').update(token).digest('hex'); 
    }
}





class WordpressLoggedInCookie{

    /**
     * Take in the wordpress_logged_in_[hash] cookie as a string & parse it.
     * @param {String} loggedInCookie 
     */
    constructor(loggedInCookie, wpSalt){
        if(typeof loggedInCookie !== 'string' || !loggedInCookie)
            throw new TypeError("WordPress Logged In Cookie needs to be a string");
        else if(typeof wpSalt !== 'string' || !wpSalt)
            throw new TypeError("Invalid WP salt");

        const cookie = loggedInCookie.split('|');

        this.username = cookie[0];
        this.expiration = cookie[1] === 'string' ? parseFloat(cookie[1]) : undefined;
        this.token = cookie[2];
        this.hmac = cookie[3];
        this.scheme = cookie[4];

        if(
            this.username === undefined || 
            this.expiration === undefined || 
            this.token === undefined || 
            this.hmac === undefined || 
            this.scheme === undefined)
                throw new Error("Cookie Invalid");
    }

    /**
     * Get the Wordpress username of the cookie
     * @returns {String} Wordpress username of the cookie
     */
    getUsername(){
        return this.username;
    }

    /**
     * Authenicate the cookie against the given user information
     * @param {number} userId The wordpress ID of the user in [prefix]_users
     * @param {*} hashedPass The hashed password of the user in [prefix]_users
     * @param {*} sessionToken The session token of the user in [prefix]_metadata
     * @returns {Boolean} 
     */
    authenticate(userId, hashedPass, sessionToken){
        // Validate inputs
        if( 
            typeof userId !== 'number' || 
            typeof hashedPass !== 'string' || 
            typeof sessionToken !== 'string'
        )
            return false;

        // Check if expired
        if(this.expiration < parseInt(Date.now()/1000))
            return false;
        
        // Get last 4 of hash from user pass (last 4 since using non-vanilla bcrypt)
        const passFrag = hashedPass.slice(-4);
    
        // Create key - $key = wp_hash( $username . '|' . $pass_frag . '|' . $expiration . '|' . $token, $scheme );
        const key = WordpressAuth.calculateHMAC(
            'md5', 
            WordpressAuth.wpSalt,
            `${this.username}|${passFrag}|${this.expiration}|${this.token}`
        );

        // Create hash - hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );
        const hash = WordpressAuth.calculateHMAC(
            'sha256', 
            key, 
            `${this.username}|${this.expiration}|${this.token}`
        );
        
        // Compare calculated hash to the one we got
        if(hash !== this.hmac)
            return false;
        
        // Check hashed token against whats stored in the usermeta table under sessions
        if(!sessionToken.includes(WordpressAuth.hashToken(this.token)))
            return false;

        return true;
    }
}

