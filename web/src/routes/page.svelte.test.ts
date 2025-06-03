import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import { beforeEach, describe, expect, test } from 'vitest';
import Page from './+page.svelte';

describe('/+page.svelte', () => {
    beforeEach(() => {
        render(Page);
    });

    test('renders the page with the correct title', () => {
        const title = document.querySelector('title');
        expect(title).toBeTruthy();
        expect(title).toHaveTextContent('EchoHub');
    });

    test('renders the main heading', () => {
        const heading = screen.getByRole('heading', {
            name: 'Welcome to EchoHub',
        });
        expect(heading).toBeInTheDocument();
    });

    test('renders the login/signup links', () => {
        const siginLink = screen.getByRole('link', {
            name: 'Sign in',
        });
        const signupLink = screen.getByRole('link', {
            name: 'Sign up',
        });
        expect(siginLink).toBeInTheDocument();
        expect(signupLink).toBeInTheDocument();
    });
});
