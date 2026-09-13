import { defineConfig } from 'vitest/config';
import fs from 'fs';

export default defineConfig({
    plugins: [
        {
            name: 'mustache-raw-loader',
            transform(_code, id) {
                if (id.endsWith('.mustache')) {
                    const content = fs.readFileSync(id, 'utf-8');
                    return {
                        code: `export default ${JSON.stringify(content)};`,
                    };
                }
            },
        },
    ],
    test: {
        globals: true,
        environment: 'node',
    },
});
