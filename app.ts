/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import helmet from 'helmet';

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic');
  await validateDependencies();

  const server = await import('./server');
  const expressApp = await server.start();

  // Use helmet middleware to secure HTTP headers
  expressApp.use(helmet());

  // You can configure Helmet's default settings here if needed, like:
  // expressApp.use(helmet({ contentSecurityPolicy: false }));

}

app()
  .catch(err => {
    throw err;
  });

