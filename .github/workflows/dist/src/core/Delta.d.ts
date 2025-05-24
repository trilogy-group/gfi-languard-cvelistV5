/**
 *  This is the Delta class.  A delta is a list of files in a directory whose content changed from time T1 to T2.
 *  Changes can be a new added file, updated file, or deleted file (though currently, we do not work with deleted
 *  files since no CVEs should ever be deleted once it is published).
 *
 *  When making zip files, this class copies CVE JSON files from /cves to a directory, and zip that, so the /cves directory
 *  needs to be in the current directory
 */
import { CveCorePlus } from './CveCorePlus.js';
export declare type IsoDate = string;
export declare enum DeltaQueue {
    kNew = 1,
    kPublished = 2,
    kUpdated = 3,
    kError = 4
}
/**
 * Output JSON format for delta.json and deltaLog.json based on feedback
 * from the AWG on 8/22/2023 to keep the output simple
 *
 * So internally, we are storing the full CveCorePlus, but externally,
 * and specifically when writing out to JSON, we are using this shortened format
 
 * see https://github.com/CVEProject/cvelistV5/issues/23 for some additional discussions
 * before and after the AWG meeting on 8/22
 */
export declare class DeltaOutpuItem {
    static _cveOrgPrefix: string;
    static _githubRawJsonPrefix: string;
    cveId: string;
    cveOrgLink?: string;
    githubLink?: string;
    dateUpdated?: string;
    static fromCveCorePlus(cvep: CveCorePlus): DeltaOutpuItem;
    static replacer(key: string, value: any): any;
    toJSON(): {
        cveId: string;
        cveOrgLink: string;
        githubLink: string;
        dateUpdated: string;
    };
}
export declare class Delta {
    /** max message length for github commit messages
     *  needed to truncate commit message when too many CVEs
     *  were changed
     */
    static kMaxGithubCommitMessageLength: number;
    fetchTime?: string;
    numberOfChanges: number;
    new: CveCorePlus[];
    updated: CveCorePlus[];
    error?: CveCorePlus[];
    /** constructor
     *  @param prevDelta a previous delta to intialize this object, essentially prepending new
     *                   deltas to the privous ones (default is none)
     */
    constructor(prevDelta?: Partial<Delta>);
    static fromDeltaFile(relFilepath: string): Delta | undefined;
    /**
     * updates data in new and updated lists using CVE ID
     */
    hydrate(): void;
    /** returns useful metadata given a repository filespec:
     *   - its CVE ID (for example, CVE-1970-0001)
     *   - its partial path in the repository (for example, ./abc/def/CVE-1970-0001)
     *  @param path a full or partial filespec (for example, ./abc/def/CVE-1970-0001.json)
     *  @todo should be in a separate CveId or CveRecord class
     */
    static getCveIdMetaData(path: string): [string | undefined, string | undefined];
    /**
     * pure function:  given origQueue, this will either add cve if it is not already in origQueue
     * or replace the original in origQueue with cve
     * @param cve the CVE to be added/replaced
     * @param origQueue the original queue
     * @returns a typle:
     *    [0] is the new queue (with the CVE either added or replace older)
     *    [1] either 0 if CVE is replaced, or 1 if new, intended to be += to this.numberOfChanges (deprecated)
     */
    private _addOrReplace;
    /** calculates the numberOfChanges property
     * @returns the total number of deltas in all the queues
     */
    calculateNumDelta(): number;
    /** adds a cveCore object into one of the queues in a delta object
     *  @param cve a CveCore object to be added
     *  @param queue the DeltaQueue enum specifying which queue to add to
     */
    add(cve: CveCorePlus, queue: DeltaQueue): void;
    /**
     * returns all CVEs from new and updated queues
     */
    getAllUniqueNewAndUpdatedCves(): Array<CveCorePlus>;
    /** summarize the information in this Delta object in human-readable form */
    toText(): string;
}
