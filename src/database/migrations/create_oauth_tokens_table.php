<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * `expires_at` is the moment the access token stops being accepted, which is
     * what the refresh middleware reads. A null expiry is treated as expired,
     * so a token stored without one is renewed on the owner's next request.
     *
     * `refresh_token` is nullable because the identity provider is not obliged
     * to issue one; without it the session simply ends when the access token
     * does, and the user is sent back through the SSO flow.
     */
    public function up(): void
    {
        Schema::create('oauth_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete()->cascadeOnUpdate();
            $table->text('access_token');
            $table->text('refresh_token')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('oauth_tokens');
    }
};
