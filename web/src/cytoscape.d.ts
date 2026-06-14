// Minimal ambient declarations so we can use cytoscape without pulling @types packages.
declare module 'cytoscape' {
  const cytoscape: any
  export default cytoscape
}
declare module 'cytoscape-cose-bilkent' {
  const ext: any
  export default ext
}
