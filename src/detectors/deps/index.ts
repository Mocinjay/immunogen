/** Barrel re-export of osvDetector (CAT-5 DEP-01: OSV.dev dependency vulnerability detector). */
export { osvDetector } from "./osv-detector.js";
/** Barrel re-export of the OSV.dev batch client (DEP-01's network boundary; stubbed in tests). */
export { OsvUnavailableError, queryOsvBatch } from "./osv-client.js";
/** Barrel re-export of the bundled offline fallback list + comparator (DEP-01's offline-degradation path). */
export { checkFallback, FALLBACK_VULNERABLE_NPM } from "./osv-fallback.js";
