/** HTML files loaded as text strings by the static-text esbuild plugin */
declare module '*.html' {
  const content: string;
  export default content;
}
