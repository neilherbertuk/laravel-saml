<?php

namespace KingStarter\LaravelSaml\Http\Traits;

use Storage;
use Illuminate\Http\Request;
use LightSaml\Model\Protocol\Response as Response;
use LightSaml\Credential\X509Certificate;

// For debug purposes, include the Log facade
use Illuminate\Support\Facades\Log;

trait SamlAuth
{
    /**
     * SamlAuth constructor.
     * @param Request $request
     */
    public function __construct(Request $request)
    {
        // Store RelayState to session if provided
        if(!empty($request->input('RelayState'))){
            session()->put('RelayState', $request->input('RelayState'));
        }
    }

    /*
    |--------------------------------------------------------------------------
    | File handling (metadata, certificates)
    |--------------------------------------------------------------------------
    */
    
    /**
     * Get either the url or the content of a given file.
     */    
    protected function getSamlFile($configPath, $url) {
        if ($url)
            return Storage::disk('saml')->url($configPath);
        return Storage::disk('saml')->get($configPath);
    }    
    
    /**
     * Get either the url or the content of the saml metadata file.
     *
     * @param boolean url   Set to true to get the metadata url, otherwise the
     *                      file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function metadata($url = false) {
        return $this->getSamlFile(config('saml.idp.metadata'), $url);
    }
    
    /**
     * Get either the url or the content of the certificate file.
     *
     * @param boolean url   Set to true to get the certificate url, otherwise the
     *                      file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function certfile($url = false) {
        return $this->getSamlFile(config('saml.idp.cert'), $url);
    }

    /**
     * Get either the url or the content of the certificate keyfile.
     *
     * @param boolean url   Set to true to get the certificate key url, otherwise
     *                      the file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function keyfile($url = false) {
        return $this->getSamlFile(config('saml.idp.key'), $url);
    }
    
    /*
    |--------------------------------------------------------------------------
    | Saml authentication
    |--------------------------------------------------------------------------
    */    

    /**
     * Handle an http request as saml authentication request. Note that the method
     * should only be called in case a saml request is also included. 
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */    
    public function handleSamlLoginRequest($request) {
        if (isset($request->SAMLRequest)) {
            // Get and decode the SAML request
            $SAML = $request->SAMLRequest;
            $decoded = base64_decode($SAML);
            $xml = gzinflate($decoded);
            // Initiate context and authentication request object
            $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
            $deserializationContext->getDocument()->loadXML($xml);
            $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
            $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);
            // Generate the saml response (saml authentication attempt)
            $this->buildSamlResponse($authnRequest, $request);
        }
    }

    /**
     * Make a saml authentication attempt by building the saml response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     * @see https://www.lightsaml.com/LightSAML-Core/Cookbook/How-to-make-Response/
     * @see https://imbringingsyntaxback.com/implementing-a-saml-idp-with-laravel/
     */
    protected function buildSamlResponse($authnRequest, $request)
    {
        // Get corresponding destination and issuer configuration from SAML config file for assertion URL
        // Note: Simplest way to determine the correct assertion URL is a short debug output on first run
        $destination = config('saml.sp.'.base64_encode($authnRequest->getAssertionConsumerServiceURL()).'.destination');
        $issuer = config('saml.sp.'.base64_encode($authnRequest->getAssertionConsumerServiceURL()).'.issuer');

        // Load in both certificate and keyfile
        // The files are stored within a private storage path, this prevents from
        // making them accessible from outside  
        $x509 = new X509Certificate();
        $certificate = $x509->loadPem($this->certfile());
        // Load in keyfile content (last parameter determines of the first one is a file or its content)
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey($this->keyfile(), '', false);

        if (config('saml.debug_saml_request')) {
            Log::debug('<SamlAuth::buildSAMLResponse>');
            Log::debug('Assertion URL: ' . $authnRequest->getAssertionConsumerServiceURL());
            Log::debug('Assertion URL: ' . base64_encode($authnRequest->getAssertionConsumerServiceURL()));
            Log::debug('Destination: ' . $destination);
            Log::debug('Issuer: ' . $issuer);
            Log::debug('Certificate: ' . $this->certfile());
        }

        // Generate the response object
        $response = new \LightSaml\Model\Protocol\Response();
        $response
           ->addAssertion($assertion = new \LightSaml\Model\Assertion\Assertion())
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($destination)
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
            ->setStatus(new \LightSaml\Model\Protocol\Status(new \LightSaml\Model\Protocol\StatusCode(\LightSaml\SamlConstants::STATUS_SUCCESS)))
            ->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey))
        ;

        $this->addRelayStateToResponse($response);

        // Generate the SAML assertion for the response xml object
        $this->assertId($assertion);

        $this->assertIssueInstance($assertion);

        $this->assertIssuer($assertion, $issuer);

        $this->assertSubject($assertion, $authnRequest->getId(), $authnRequest->getAssertionConsumerServiceURL());

        $this->assertConditions($assertion, $authnRequest->getAssertionConsumerServiceURL());

        // Add AuthnStatement to Response
        $this->assertAuthnStatement($assertion);

        // Add Roles to Response
        $this->assertRoles($assertion, $authnRequest->getAssertionConsumerServiceURL());

        // Add Attributes to Response
        $this->assertAttributes($assertion, $authnRequest->getAssertionConsumerServiceURL());

        // Send out the saml response
            $this->sendSamlResponse($response);
    }

    /**
     * Send saml response object (print out)
     *
     * @param  \LightSaml\Model\Protocol\Response  $response
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendSamlResponse(Response $response)
    {
        $bindingFactory = new \LightSaml\Binding\BindingFactory();
        $postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
        $messageContext = new \LightSaml\Context\Profile\MessageContext();
        $messageContext->setMessage($response)->asResponse();
        /** @var \Symfony\Component\HttpFoundation\Response $httpResponse */
        $httpResponse = $postBinding->send($messageContext);
        print $httpResponse->getContent()."\n\n";
    }

    /**
     * @param $response
     */
    protected function addRelayStateToResponse($response)
    {
        if (session()->has('RelayState')) {
            $response->setRelayState(session()->get('RelayState'));
            session()->remove('RelayState');
        }
    }

    /**
     * @param $assertion
     */
    protected function assertId($assertion)
    {
        $assertion->setId(\LightSaml\Helper::generateID());
    }

    /**
     * @param $assertion
     */
    protected function assertIssueInstance($assertion)
    {
        $assertion->setIssueInstant(new \DateTime());
    }

    /**
     * @param $assertion
     * @param $issuer
     */
    protected function assertIssuer($assertion, $issuer)
    {
        $assertion->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer));
    }

    /**
     * @param $assertion
     * @param $id
     * @param $sp
     */
    protected function assertSubject($assertion, $id, $sp)
    {
        $assertion->setSubject(
            (new \LightSaml\Model\Assertion\Subject())
                ->setNameID(new \LightSaml\Model\Assertion\NameID(
                    \Auth::user()->{config('saml.sp.' . base64_encode($sp) . '.name_id_field', 'email')} ?: 'Unknown',
                    constant("\LightSaml\SamlConstants::" . config('saml.sp.' . base64_encode($sp) . '.name_id_format', 'NAME_ID_FORMAT_EMAIL'))
                ))
                ->addSubjectConfirmation(
                    (new \LightSaml\Model\Assertion\SubjectConfirmation())
                        ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                        ->setSubjectConfirmationData(
                            (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                ->setInResponseTo($id)
                                ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                                ->setRecipient($sp)
                        )
                )
        );
    }

    /**
     * @param $assertion
     * @param $sp
     */
    protected function assertConditions($assertion, $sp)
    {
        $assertion->setConditions(
            (new \LightSaml\Model\Assertion\Conditions())
                ->setNotBefore(new \DateTime())
                ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                ->addItem(
                    new \LightSaml\Model\Assertion\AudienceRestriction([
                        config('saml.sp.' . base64_encode($sp) . '.audience_restriction',
                            $sp)])
                )
        );
    }

    /**
     * @param $assertion
     */
    protected function assertAuthnStatement($assertion)
    {
        $assertion->addItem(
            (new \LightSaml\Model\Assertion\AuthnStatement())
                ->setAuthnInstant(new \DateTime('-10 MINUTE'))
                ->setSessionIndex(session()->getId())
                ->setAuthnContext(
                    (new \LightSaml\Model\Assertion\AuthnContext())
                        ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                )
        );
    }

    /**
     * @param $assertion
     * @param $sp
     * @internal param $roles
     */
    protected function assertRoles($assertion, $sp)
    {
        if ($this->shouldForwardRoles($sp)) {
            $assertion->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        \LightSaml\ClaimTypes::ROLE,
                        \Auth::user()->roles->pluck('name')->all() ?: array()
                    ))
            );
        }
    }

    /**
     * @param $sp
     * @return \Illuminate\Config\Repository|mixed
     */
    protected function shouldForwardRoles($sp)
    {
        return config('saml.sp.' . base64_encode($sp) . '.forward_roles', config('saml.forward_roles'));
    }

    /**
     * @param $assertion
     * @param $sp
     * @internal param $user
     */
    protected function assertAttributes($assertion, $sp)
    {
        $attributes = config('saml.sp.' . base64_encode($sp) . '.attributes', ['EMAIL_ADDRESS' => 'email', 'COMMON_NAME' => 'name',]);
        foreach ($attributes as $key => $value) {
            $assertion->addItem(
                (new \LightSaml\Model\Assertion\AttributeStatement())
                    ->addAttribute(new \LightSaml\Model\Assertion\Attribute(
                        constant("\LightSaml\ClaimTypes::$key"),
                        \Auth::user()->$value ?: 'Unknown'
                    ))
            );
        }
    }
}
