<svelte:head>
    <title>EchoHub</title>
</svelte:head>

<div class="title-container">
    <h1>Welcome to EchoHub</h1>
</div>
<div class="auth-links">
    <div class="links-container">
        <div class="link-item">
            <a href="/signup" aria-label="Sign up">Sign up</a>
        </div>
        <div class="link-item">
            <a href="/signin" aria-label="Sign in">Sign in</a>
        </div>
    </div>
</div>

<style lang="scss">
    .title-container {
        text-align: center;
        margin-top: 50px;

        h1 {
            font-size: 2.5rem;
            color: $clr-light-a0;
        }
    }

    .auth-links {
        display: flex;
        justify-content: center;
        margin-top: 20px;

        .links-container {
            display: flex;
            gap: 20px;

            .link-item {
                border: 2px solid $clr-primary-a0;
                padding: 10px 20px;
                border-radius: 5px;
                background-color: $clr-primary-a0;
                a {
                    text-decoration: none;
                    color: $clr-dark-a0;
                    font-size: 1.2rem;
                    transition: color 0.3s ease;

                    &:hover {
                        color: $clr-light-a0;
                    }
                }
            }
        }
    }
</style>
