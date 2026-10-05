<?php

namespace Uzairports\Uzairid\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Answer a mobile client in JSON whatever `Accept` it sent.
 *
 * The endpoints behind `Uzair::apiRoutes()` share their sign-out answers,
 * validation, throttling and authentication failures with the browser ones,
 * which all ask `expectsJson()` / `wantsJson()`. A client that omitted the
 * header was answered with a redirect it cannot follow.
 */
class TreatRequestAsJson
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $request->headers->set('Accept', 'application/json');

        return $next($request);
    }
}
