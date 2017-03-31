<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | https://github.com/hybridauth/hybridauth
*  (c) 2009-2011 HybridAuth authors | hybridauth.sourceforge.net/licenses.html
*/

/**
 * Hybrid_Providers_Justia
 */
class Hybrid_Providers_Justia extends Hybrid_Provider_Model_OAuth2 {
    // default permissions
    public $scope = "basic,email,read_profiles";

    /**
     * IDp wrappers initializer
     */
    function initialize() {
        if (!$this->config["keys"]["id"] || !$this->config["keys"]["secret"]) {
            throw new Exception(
                "Your application id and secret are required in order to connect to {$this->providerId}.", 4);
        }

        // override requested scope
        if (isset($this->config["scope"]) && !empty($this->config["scope"])) {
            $this->scope = $this->config["scope"];
        }

        // include OAuth2 client
        require_once Hybrid_Auth::$config["path_libraries"] . "OAuth/OAuth2Client.php";
        require_once Hybrid_Auth::$config["path_libraries"] . "Justia/JustiaOAuth2Client.php";

        // create a new OAuth2 client instance
        $this->api = new JustiaOAuth2Client($this->config["keys"]["id"],
                                            $this->config["keys"]["secret"],
                                            $this->endpoint,
                                            $this->compressed);

        // If we have an access token, set it
        if ($this->token("access_token")) {
            $this->api->access_token = $this->token("access_token");
            $this->api->refresh_token = $this->token("refresh_token");
            $this->api->access_token_expires_in = $this->token("expires_in");
            $this->api->access_token_expires_at = $this->token("expires_at");
        }

        // Set curl proxy if exist
        if (isset(Hybrid_Auth::$config["proxy"])) {
            $this->api->curl_proxy = Hybrid_Auth::$config["proxy"];
        }

        // Provider api endpoints and state
        $this->api->api_base_url  = "https://accounts.justia.com/api/v1.0/me";
        $this->api->authorize_url = "https://accounts.justia.com/oauth/authorize";
        $this->api->token_url     = "https://accounts.justia.com/oauth/access_token";
        $this->api->state         = md5(time());
    }

    /**
     * load the user profile from the IDp api client
     */
    function getUserProfile() {
        $this->api->curl_header = array(
            'Response-Type: json',
            'Connection: Keep-Alive',
            'Authorization: Bearer ' . $this->api->access_token,
        );
        $data = $this->api->api( "user" );

        if (!isset($data->id)) {
            throw new Exception( "User profile request failed! {$this->providerId} returned an invalid response.", 6);
        }

        $this->user->profile->identifier  = @ $data->uid;
        $this->user->profile->displayName = @ $data->name;
        $this->user->profile->firstName   = @ $data->firstname;
        $this->user->profile->lastName    = @ $data->lastname;
        $this->user->profile->email       = @ $data->email;
        $this->user->profile->description = @ $data->bio;

        if(empty($this->user->profile->displayName)) {
            $this->user->profile->displayName = (@ $data->firstname) . " " . @ $data->lastname;
        }

        return $this->user->profile;
    }

    /**
     * {@inheritdoc}
     */
    function loginBegin() {
        $params = array("scope" => $this->scope, "state" => $this->api->state);
        // redirect the user to the provider authentication url
        Hybrid_Auth::redirect($this->api->authorizeUrl($params));
    }
}
