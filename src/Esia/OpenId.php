<?php

namespace Esia;

use Esia\Exceptions\AbstractEsiaException;
use Esia\Exceptions\ExpiredTokenException;
use Esia\Exceptions\ForbiddenException;
use Esia\Exceptions\RequestFailException;
use Esia\Http\GuzzleHttpClient;
use Esia\Signer\Exceptions\CannotGenerateRandomIntException;
use Esia\Signer\Exceptions\SignFailException;
use Esia\Signer\SignerInterface;
use Esia\Signer\SignerPKCS7;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use RuntimeException;

/**
 * Class OpenId
 */
class OpenId
{
    use LoggerAwareTrait;

    /**
     * @var SignerInterface
     */
    private $signer;

    /**
     * Http Client
     *
     * @var ClientInterface
     */
    private $client;

    /**
     * Config
     *
     * @var Config
     */
    private $config;

    /**
     * Массив для тестовых данных
     */
    private $test = [];

    public function __construct(Config $config, ClientInterface $client = null)
    {
        $this->config = $config;
        $this->client = $client ?? new GuzzleHttpClient(new Client());
        $this->logger = new NullLogger();
        $this->signer = new SignerPKCS7(
            $config->getCertPath(),
            $config->getPrivateKeyPath(),
            $config->getPrivateKeyPassword(),
            $config->getTmpPath()
        );
    }

    /**
     * Установка тестовых данных (включается режим теста)
     * В тестовом режиме подписание не производится и запросы в ЕСИА не отправляются, данные отдаются
     * из массива test
     *
     * @param $testData
     */
    public function setTest($testData)
    {
        $this->test = $testData;
    }

    /**
     * Получить значение тестового массива (в каком режиме находится объект)
     *
     * @return array
     */
    public function getTest(): array
    {
        return $this->test;
    }

    /**
     * Replace default signer
     */
    public function setSigner(SignerInterface $signer): void
    {
        $this->signer = $signer;
    }

    /**
     * Get config
     */
    public function getConfig(): Config
    {
        return $this->config;
    }

    /**
     * Return an url for authentication
     *
     * ```php
     *     <a href="<?=$esia->buildUrl()?>">Login</a>
     * ```
     *
     * @return string|false
     * @throws SignFailException
     */
    public function buildUrl()
    {
        $timestamp = $this->getTimeStamp();
        $state = $this->buildState();
        $message = $this->config->getScopeString()
            . $timestamp
            . $this->config->getClientId()
            . $state;

        $clientSecret = $this->signer->sign($message);

        $url = $this->config->getCodeUrl() . '?%s';

        $params = [
            'client_id' => $this->config->getClientId(),
            'client_secret' => $clientSecret,
            'redirect_uri' => $this->config->getRedirectUrl(),
            'scope' => $this->config->getScopeString(),
            'response_type' => $this->config->getResponseType(),
            'state' => $state,
            'access_type' => $this->config->getAccessType(),
            'timestamp' => $timestamp,
        ];

        $request = http_build_query($params);

        return sprintf($url, $request);
    }

    /**
     * Return an url for logout
     */
    public function buildLogoutUrl(string $redirectUrl = null): string
    {
        $url = $this->config->getLogoutUrl() . '?%s';
        $params = [
            'client_id' => $this->config->getClientId(),
        ];

        if ($redirectUrl) {
            $params['redirect_url'] = $redirectUrl;
        }

        $request = http_build_query($params);

        return sprintf($url, $request);
    }

    /**
     * Method collect a token with given code
     *
     * @throws SignFailException
     * @throws AbstractEsiaException
     */
    public function getToken(string $code): string
    {
        if ($this->test) return $this->test['token'] ?? '';

        $timestamp = $this->getTimeStamp();
        $state = $this->buildState();

        $clientSecret = $this->signer->sign(
            $this->config->getScopeString()
            . $timestamp
            . $this->config->getClientId()
            . $state
        );

        $body = [
            'client_id' => $this->config->getClientId(),
            'code' => $code,
            'grant_type' => 'authorization_code',
            'client_secret' => $clientSecret,
            'state' => $state,
            'redirect_uri' => $this->config->getRedirectUrl(),
            'scope' => $this->config->getScopeString(),
            'timestamp' => $timestamp,
            'token_type' => 'Bearer',
            'refresh_token' => $state,
        ];

        $payload = $this->sendRequest(
            new Request(
                'POST',
                $this->config->getTokenUrl(),
                [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                http_build_query($body)
            )
        );

        $this->logger->debug('Payload: ', $payload);

        $token = $payload['access_token'];
        $this->config->setToken($token);
        $this->config->setRefresh($payload['refresh_token']);

        # get object id from token
        $chunks = explode('.', $token);
        $payload = json_decode($this->base64UrlSafeDecode($chunks[1]), true);
        $this->config->setOid($payload['urn:esia:sbj_id']);

        return $token;
    }

    public function refreshToken()
    {
        // TODO: можно реализовать процесс генерации токена
        if ($this->test) return $this->test['token'] ?? '';

        $timestamp = $this->getTimeStamp();
        $state = $this->buildState();

        $clientSecret = $this->signer->sign(
            $this->config->getScopeString()
            . $timestamp
            . $this->config->getClientId()
            . $state
        );

        $body = [
            'client_id' => $this->config->getClientId(),
            'code' => $this->getRefresh(),
            'grant_type' => 'refresh_token',
            'client_secret' => $clientSecret,
            'state' => $state,
            'redirect_uri' => $this->config->getRedirectUrl(),
            'scope' => $this->config->getScopeString(),
            'timestamp' => $timestamp,
            'token_type' => 'Bearer',
            'refresh_token' => $this->getRefresh(),
        ];

        $payload = $this->sendRequest(
            new Request(
                'POST',
                $this->config->getTokenUrl(),
                [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                http_build_query($body)
            )
        );

        $this->logger->debug('Payload refresh: ', $payload);

        $token = $payload['access_token'];
        $this->config->setToken($token);
        $this->config->setRefresh($payload['refresh_token']);

        # get object id from token
        // $chunks = explode('.', $token);
        // $payload = json_decode($this->base64UrlSafeDecode($chunks[1]), true);
        // $this->config->setOid($payload['urn:esia:sbj_id']);

        return $token;

    }

    public function setToken($token)
    {
        $this->config->setToken($token);
    }

    public function setRefresh($refresh)
    {
        $this->config->setRefresh($refresh);
    }

    /**
     * Возвращает рефреш для обновления токена. Вероятно, механизм обновления токена нужно реализовать
     * скрытно в данном классе, тогда этот метод потеряет значимость
     *
     * @return string
     */
    public function getRefresh(): string
    {
        if ($this->test) return $this->test['refresh'] ?? '';

        return $this->config->getRefresh();
    }

    /**
     * Fetch person info from current person
     *
     * You must collect token person before
     * calling this method
     *
     * @throws AbstractEsiaException
     */
    public function getPersonInfo(): array
    {
        if ($this->test) return $this->test['person'] ?? [];

        $url = $this->config->getPersonUrl();

        $result = $this->sendRequest(new Request('GET', $url));
        return $result;
    }

    /**
     * Fetch contact info about current person
     *
     * You must collect token person before
     * calling this method
     *
     * @throws Exceptions\InvalidConfigurationException
     * @throws AbstractEsiaException
     */
    public function getContactInfo(): array
    {
        if ($this->test) return $this->test['contacts'] ?? [];

        $url = $this->config->getPersonUrl() . '/ctts';
        $payload = $this->sendRequest(new Request('GET', $url));

        if ($payload && $payload['size'] > 0) {
            return $this->collectArrayElements($payload['elements']);
        }

        return $payload;
    }


    /**
     * Fetch address from current person
     *
     * You must collect token person before
     * calling this method
     *
     * @throws Exceptions\InvalidConfigurationException
     * @throws AbstractEsiaException
     */
    public function getAddressInfo(): array
    {
        if ($this->test) return $this->test['addresses'] ?? [];

        $url = $this->config->getPersonUrl() . '/addrs';
        $payload = $this->sendRequest(new Request('GET', $url));

        if ($payload['size'] > 0) {
            return $this->collectArrayElements($payload['elements']);
        }

        return $payload;
    }

    /**
     * Fetch documents info about current person
     *
     * You must collect token person before
     * calling this method
     *
     * @throws Exceptions\InvalidConfigurationException
     * @throws AbstractEsiaException
     */
    public function getDocInfo(): array
    {
        if ($this->test) return $this->test['docs'] ?? [];

        $url = $this->config->getPersonUrl() . '/docs';

        $payload = $this->sendRequest(new Request('GET', $url));

        if ($payload && $payload['size'] > 0) {
            return $this->collectArrayElements($payload['elements']);
        }

        return $payload;
    }


    public function getOrgInfo(): array
    {
        if ($this->test) return $this->test['orgs'] ?? [];

        $url = $this->config->getPersonUrl() . '/roles';

        $payload = $this->sendRequest(new Request('GET', $url));

        if ($payload && $payload['size'] > 0) {
            return $payload;
        }

        return $payload;
    }


    /**
     * Получение общих данных по организации (ИНН, КПП, тип, название и т.д.)
     *
     * @param $orgOid
     * @return array
     * @throws AbstractEsiaException
     */
    public function getOrgInfoFull($orgOid): array
    {
        if ($this->test) {
            foreach ($this->test['orgs']['elements'] as $key => $element) {
                if ($element['oid'] == $orgOid) {
                    // TODO: Уточнить возвращаемые данные
                    return [
                        'inn' => $element['inn'] ?? '',
                        'kpp' => $element['kpp'] ?? '',
                    ];
                }
            }
            return [];
        }

        $url = $this->config->getPortalUrl() . 'rs/orgs/' . $orgOid;

        $payload = $this->sendRequest(new Request('GET', $url));

        return $payload;
    }

    /**
     * Получение коллекции контактов по организации, в виде списка ссылок на ресурс
     *
     * @param $orgOid
     * @return array
     * @throws AbstractEsiaException
     */
    public function getOrgInfoCtts($orgOid): array
    {
        $url = $this->config->getPortalUrl() . 'rs/orgs/' . $orgOid . '/ctts?embed=(elements)';
        $payload = $this->sendRequest(new Request('GET', $url));
        if ($payload['size'] > 0) {
//            $payload['data'] = [];
//            foreach ($payload['elements'] as $urlCtt) {
//                $ctt = $this->sendRequest(new Request('GET', $urlCtt));
//                $ctt['url'] = $urlCtt;
//                $payload['data'][] = $ctt;
//            }
        }
        return $payload;
    }

    /**
     * Получение коллекции адресов по организации, в виде списка ссылок на ресурс
     *
     * @param $orgOid
     * @return array
     * @throws AbstractEsiaException
     */
    public function getOrgInfoAddrs($orgOid)
    {
        $url = $this->config->getPortalUrl() . 'rs/orgs/' . $orgOid . '/addrs?embed=(elements)';
        $payload = $this->sendRequest(new Request('GET', $url));
        if ($payload['size'] > 0) {
//            $payload['data'] = [];
//            foreach ($payload['elements'] as $urlCtt) {
//                $ctt = $this->sendRequest(new Request('GET', $urlCtt));
//                $ctt['url'] = $urlCtt;
//                $payload['data'][] = $ctt;
//            }
        }
        return $payload;
    }

    /**
     *
     * embed=(elements.address,elements.contact)
     *
     * @param $orgOid
     * @return array
     * @throws AbstractEsiaException
     */
    public function getOrgInfoEmps($orgOid)
    {
        $url = $this->config->getPortalUrl() . 'rs/orgs/' . $orgOid . '/emps?embed=(elements.person)';
        $payload = $this->sendRequest(new Request('GET', $url));
        if ($payload['size'] > 0) {
//            $payload['data'] = [];
//            foreach ($payload['elements'] as $urlCtt) {
//                $ctt = $this->sendRequest(new Request('GET', $urlCtt));
//                $ctt['url'] = $urlCtt;
//                $payload['data'][] = $ctt;
//            }
        }
        return $payload;
    }

    /**
     * This method can iterate on each element
     * and fetch entities from esia by url
     *
     * @throws AbstractEsiaException
     */
    private function collectArrayElements($elements): array
    {
        $result = [];
        foreach ($elements as $elementUrl) {
            $elementPayload = $this->sendRequest(new Request('GET', $elementUrl));

            if ($elementPayload) {
                $result[] = $elementPayload;
            }
        }

        return $result;
    }

    /**
     * @throws AbstractEsiaException
     */
    private function sendRequest(RequestInterface $request): array
    {
        try {
            if ($this->config->getToken()) {
                /** @noinspection CallableParameterUseCaseInTypeContextInspection */
                $request = $request->withHeader('Authorization', 'Bearer ' . $this->config->getToken());
            }
            $response = $this->client->sendRequest($request);
            $responseBody = json_decode($response->getBody()->getContents(), true);

            if (!is_array($responseBody)) {
                throw new RuntimeException(
                    sprintf(
                        'Cannot decode response body. JSON error (%d): %s',
                        json_last_error(),
                        json_last_error_msg()
                    )
                );
            }

            return $responseBody;
        } catch (ClientExceptionInterface $e) {
            $this->logger->error('Request was failed', ['exception' => $e]);
            $prev = $e->getPrevious();

            // Only for Guzzle
            if ($prev instanceof BadResponseException
                && $prev->getResponse() !== null
                && $prev->getResponse()->getStatusCode() === 403
            ) {
                throw new ForbiddenException('Request is forbidden', 0, $e);
            }

            //$s = $s . $e->getMessage() . '------' . $e->getCode() . $prev->getMessage() . $prev->getCode();
            if ($e->getCode() == 401)
                throw new ExpiredTokenException('Token possible expired and need to refresh', 0, $e);
            else
                throw new RequestFailException('Request is failed', 0, $e);

        } catch (RuntimeException $e) {
            $this->logger->error('Cannot read body', ['exception' => $e]);
            throw new RequestFailException('Cannot read body', 0, $e);
        } catch (InvalidArgumentException $e) {
            $this->logger->error('Wrong header', ['exception' => $e]);
            throw new RequestFailException('Wrong header', 0, $e);
        }
    }

    private function getTimeStamp(): string
    {
        return date('Y.m.d H:i:s O');
    }

    /**
     * Generate state with uuid
     *
     * @throws SignFailException
     */
    private function buildState(): string
    {
        try {
            return sprintf(
                '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
                random_int(0, 0xffff),
                random_int(0, 0xffff),
                random_int(0, 0xffff),
                random_int(0, 0x0fff) | 0x4000,
                random_int(0, 0x3fff) | 0x8000,
                random_int(0, 0xffff),
                random_int(0, 0xffff),
                random_int(0, 0xffff)
            );
        } catch (Exception $e) {
            throw new CannotGenerateRandomIntException('Cannot generate random integer', $e);
        }
    }

    /**
     * Url safe for base64
     */
    private function base64UrlSafeDecode(string $string): string
    {
        $base64 = strtr($string, '-_', '+/');

        return base64_decode($base64);
    }
}
