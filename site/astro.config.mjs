import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://kado-so.github.io',
  integrations: [
    starlight({
      title: 'cin',
      description: 'Encrypted config in Git, injected at runtime.',
      customCss: ['./src/styles/starlight.css'],
      editLink: {
        baseUrl: 'https://github.com/kado-so/cin/edit/main/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/kado-so/cin',
        },
      ],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', slug: '' },
            { label: 'Quick start', slug: 'quick-start' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Commands', slug: 'commands' },
            { label: 'Config model', slug: 'config-model' },
          ],
        },
      ],
    }),
  ],
});
