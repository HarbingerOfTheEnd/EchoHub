<script>
    let { children } = $props();
</script>

<svelte:head>
    <title>EchoHub</title>
    <meta name="description" content="A Discord like chat application that is completely open source" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="theme-color" content="#000000" />
</svelte:head>

{@render children()}
