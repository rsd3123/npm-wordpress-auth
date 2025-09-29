# wordpress-cookie-user-auth

## Installation

```bash
npm install wordpress-cookie-user-auth
```

## Usage
```javascript
// Import
import WordpressAuth from 'wordpress-cookie-user-auth';
```

### Create Authenticator
Create the Authenticator (per Wordpress installation). Needs the LOGGED_IN_KEY and LOGGED_IN_SALT constants from wp_config.php.

If you have multiple different Wordpress instances, each one needs a seperate authenticator.
```javascript
const wpAuthenticator = WordpressAuth.create('wpLoggedInKey', 'wpLoggedInSalt');
```

### Parse the cookie
Parse the wordpress_logged_in_[hash] cookie as a string.
```javascript
// Parse the wordpress_logged_in_[hash] cookie string
const cookie = wpAuthenticator.parseCookie('cookieString');

// Username can now be seen in cookie.username or cookie.getUsername()

```
## User Information
It's up to you to get the user information from Wordpress. 

Needed: 

user_id, hashed_pass from [prefix]_users. 

In [prefix]_usermeta, get the meta_value where meta_key='session_tokens' and user_id=[ID of user].

```javascript
// example
const user = getWordpressUser(cookie.getUsername()); // or cookie.username

```

Now authenticate the user against the cookie.
```javascript
// Returns true is the user is authenticated
const isAuthenticated = cookie.authenticate(user.id, user.hashedPass, user.sessionToken);

if(isAuthenticated){
    // User authenticated!
}
else{
    // 401 - Unauthorized
}
```