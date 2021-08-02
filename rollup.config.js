import rollupNodeResolve from "rollup-plugin-node-resolve";

export default {
	input: "js/certidude.js",
	plugins: [
		rollupNodeResolve({ jsnext: true, main: true })
	],
	output: [
		{
			file: "js/certidude_bundle.js",
			format: "iife"
		}
	]
};