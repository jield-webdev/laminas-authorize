<?php

declare(strict_types=1);

namespace Jield\Authorize\View;

use BjyAuthorize\Exception\UnAuthorizedException;
use BjyAuthorize\Guard\Controller;
use BjyAuthorize\Guard\Route;
use JetBrains\PhpStorm\Pure;
use Laminas\Authentication\AuthenticationService;
use Laminas\Http\Response as HttpResponse;
use Laminas\Mvc\Application;
use Laminas\Mvc\MvcEvent;
use Laminas\Router\Http\TreeRouteStack;
use Laminas\Session\Container;
use Laminas\Stdlib\ResponseInterface as Response;
use Laminas\View\Model\ViewModel;

final class UnauthorizedStrategy extends \BjyAuthorize\View\UnauthorizedStrategy
{
    #[Pure] public function __construct(private readonly AuthenticationService $authenticationService, private array $config)
    {
        parent::__construct('error/403' ?? $config['template']);
    }

    public function onDispatchError(MvcEvent $event): \Laminas\Http\PhpEnvironment\Response
    {
        // Do nothing if the result is a response object
        $result = $event->getResult();

        /** @var \Laminas\Http\PhpEnvironment\Response $response */
        $response = $event->getResponse();
        if ($result instanceof Response || ($response && !$response instanceof HttpResponse)) {
            return $response;
        }
        // Common view variables
        $viewVariables = [
            'error'    => $event->getParam('error'),
            'identity' => $event->getParam('identity'),
        ];
        switch ($event->getError()) {
            case Controller::ERROR:
                $viewVariables['controller'] = $event->getParam('controller');
                $viewVariables['action']     = $event->getParam('action');
                break;
            case Route::ERROR:
                $viewVariables['route'] = $event->getParam('route');
                /*
                 * When the user is not logged in, redirect to the login-page and assemble the referrer
                 */
                if (!$this->authenticationService->hasIdentity()) {
                    $url = $event->getRouter()->assemble([], ['name' => $this->config['login_route']]);

                    /** @var TreeRouteStack $router */
                    $router = $event->getRouter();

                    $redirect = $router->assemble(
                        $event->getRouteMatch()?->getParams(),
                        [
                            'name' => $event->getParam('route'),
                        ]
                    );

                    //Store the referrer in a session
                    if ($redirect) {
                        //Grab the query and append it to the URL
                        $query   = $router->getRequestUri()->getQuery();
                        $session = new Container('session');
                        /** @phpstan-ignore-next-line */
                        $session->redirect = $redirect . (empty($query) ? '' : '?' . $query);
                    }

                    $response->getHeaders()->addHeaderLine('Location', $url);
                    $response->setStatusCode(302);

                    return $response->sendHeaders();
                }
                break;
            case Application::ERROR_EXCEPTION:
                if (!$event->getParam('exception') instanceof UnAuthorizedException) {
                    return $response;
                }
                $viewVariables['reason'] = $event->getParam('exception')
                    ->getMessage();
                $viewVariables['error']  = 'error-unauthorized';
                break;
            default:
                return $response;
        }

        $model    = new ViewModel($viewVariables);
        $response = $response ?: new HttpResponse();
        $model->setTemplate($this->getTemplate());
        $event->getViewModel()->addChild($model);
        $response->setStatusCode(403);
        $event->setResponse($response);

        return $response;
    }
}
