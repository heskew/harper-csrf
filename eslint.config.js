import harperdbConfig from '@harperdb/code-guidelines/eslint';

export default [
	...harperdbConfig,
	{
		ignores: ['dist/**'],
	},
];
