# Kassadin Development Agents & Standards

## Core Development Philosophy

### We Are Building Production Software
- **No Prototypes**: Every line of code is written with production intent
- **No Shortcuts**: We implement complete solutions, not quick fixes
- **No TODOs**: We finish what we start in each session
- **No Half-Measures**: If we can't do it right, we discuss and plan before proceeding

### Our Commitment to Excellence
1. **User Experience First**: Installation should be one command, documentation should be crystal clear
2. **Complete Solutions**: We don't move to the next task until the current one is DONE
3. **Persistent Progress**: We never abandon work without explicit discussion and agreement
4. **Professional Standards**: This isn't a hobby project - we're building critical financial infrastructure

---

## Agent Roles & Responsibilities

### Human (Jacob) - Project Lead & Developer
- **Primary Responsibilities**:
  - Strategic decisions and architecture approval
  - Code review and quality gates
  - Testing and validation
  - External communication and community building
  - Final decision authority on technical choices

### AI Assistant (Claude) - Senior Developer & Architect
- **Primary Responsibilities**:
  - Code implementation following agreed patterns
  - Research and technical documentation
  - Test writing and validation
  - Performance optimization suggestions
  - Continuous integration maintenance
  - Real-time problem solving

---

## Working Agreement

### Communication Protocol
1. **Always Explicit**: No assumptions about intent - we clarify before acting
2. **Progress Updates**: Regular status updates on long-running tasks
3. **Blockers**: Immediately flag any impediments with proposed solutions
4. **Decision Points**: Clearly mark when human input is needed

### Code Development Standards

#### Before Starting Any Task
```
1. Review the current todo list
2. Confirm the task understanding
3. Check KASSADIN_DEVELOPMENT_PLAN.md for context
4. Verify all prerequisites are met
```

#### During Development
```
1. Write tests FIRST (TDD approach)
2. Implement the minimal solution that passes tests
3. Refactor for clarity and performance
4. Document any non-obvious decisions
5. Run ALL tests before considering done
```

#### Definition of "DONE"
- [ ] All tests pass
- [ ] Code is documented
- [ ] No compiler warnings
- [ ] No TODO comments
- [ ] Integration verified
- [ ] Performance acceptable
- [ ] Error handling complete
- [ ] Memory leaks checked

### Problem Resolution Protocol

When encountering issues:

1. **STOP** - Don't try random solutions
2. **ANALYZE** - Understand the root cause
3. **DISCUSS** - Present options with trade-offs
4. **DECIDE** - Make explicit choice together
5. **DOCUMENT** - Record decision and reasoning
6. **IMPLEMENT** - Execute the chosen solution

Example:
```
ISSUE: Zig's async is unstable for our networking needs

ANALYSIS: 
- Async would provide elegant coroutine-based I/O
- Current implementation has known bugs
- Alternative: Thread pool with channels

OPTIONS:
1. Use experimental async (risk: may need rewrite)
2. Thread pool pattern (proven, but more complex)
3. Single-threaded with epoll (simple, but limits throughput)

RECOMMENDATION: Option 2 - Thread pool
REASON: Production stability > code elegance

DECISION: [Awaiting human input]
```

---

## User Experience Standards

### Installation Experience
The end user should be able to install Kassadin with:
```bash
# One-line install
curl -sSL https://kassadin.io/install.sh | sh

# Or package manager
brew install kassadin        # macOS
apt install kassadin         # Ubuntu
pacman -S kassadin          # Arch
choco install kassadin      # Windows
```

### First Run Experience
```bash
$ kassadin init
Welcome to Kassadin v1.0.0 - A Cardano Node in Zig

Detecting system configuration...
✓ CPU: AMD Ryzen 9 5900X (12 cores)
✓ RAM: 32GB available (4GB required)
✓ Disk: 500GB free (100GB required)
✓ Network: Connected

Would you like to:
1) Run a full node (recommended)
2) Run a light client
3) Configure advanced settings

Choice [1]: 

Downloading initial chain data...
[████████████████████████] 100% - Ready!

Your node is ready! Run 'kassadin start' to begin.
```

### Configuration Philosophy
- **Smart Defaults**: Should work out-of-box for 90% of users
- **Progressive Disclosure**: Advanced options available but not required
- **Clear Feedback**: Always tell user what's happening
- **Graceful Errors**: Helpful messages with solutions

---

## Development Workflow

### Daily Standup Format
At the start of each session:
```markdown
## Session Start: [Date Time]

### Previous Session Summary
- Completed: [What was finished]
- Pending: [What needs continuation]

### Today's Goals
1. [Specific deliverable]
2. [Specific deliverable]
3. [Specific deliverable]

### Potential Blockers
- [Any known issues]

### End State Target
- [What will be working by session end]
```

### Code Review Checklist
Before considering any feature complete:

- [ ] **Correctness**: Does it do what it should?
- [ ] **Completeness**: Are all edge cases handled?
- [ ] **Clarity**: Can someone else understand it?
- [ ] **Consistency**: Does it match our patterns?
- [ ] **Coverage**: Are tests comprehensive?
- [ ] **Complexity**: Is it as simple as possible?
- [ ] **Configurability**: Can users customize if needed?

### Performance Standards
Every component must meet:
- Memory: No leaks, bounded growth
- CPU: Profiled and optimized
- I/O: Async where beneficial
- Startup: < 5 seconds to operational
- Shutdown: Clean in < 2 seconds

---

## Technical Guidelines

### Error Messages
```zig
// BAD
return error.Failed;

// GOOD
return error.InvalidBlockHash;

// BETTER - with context
log.err("Invalid block hash: expected 32 bytes, got {}", .{hash.len});
return error.InvalidBlockHash;
```

### Logging Standards
```zig
// Levels and when to use them
log.debug("Detailed protocol message: {}", .{msg});    // Development only
log.info("Node started on port {}", .{port});         // Key operations
log.warn("Peer {} slow to respond", .{peer_id});      // Recoverable issues
log.err("Failed to write block: {}", .{err});         // Errors needing attention
```

### Testing Philosophy
```zig
// Every public function needs tests
test "Block.validate - accepts valid block" { ... }
test "Block.validate - rejects future timestamp" { ... }
test "Block.validate - rejects invalid signature" { ... }

// Property-based tests for complex logic
test "Chain.selectBest - always picks higher density" { ... }

// Integration tests for workflows
test "Full block sync from genesis" { ... }
```

### Documentation Standards
```zig
/// Validates a block according to Ouroboros Praos rules.
/// 
/// This includes checking:
/// - Block signature validity
/// - VRF proof correctness  
/// - Timestamp within slot bounds
/// - Previous block hash linkage
///
/// Returns error.InvalidBlock if any check fails.
pub fn validateBlock(self: *Chain, block: Block) !void {
    // Implementation
}
```

---

## Continuous Improvement

### After Each Major Milestone
1. **Retrospective**: What worked? What didn't?
2. **Metrics Review**: Performance, code quality, test coverage
3. **Process Updates**: Adjust this document based on learnings
4. **Tool Evaluation**: Are our tools serving us well?

### Knowledge Capture
- Design decisions go in `docs/decisions/`
- Learnings go in `docs/learnings/`
- Patterns go in `docs/patterns/`

### Community Engagement
- Weekly progress updates (blog/social)
- Monthly technical deep-dives
- Respond to issues within 48 hours
- Welcome contributors warmly

---

## Emergency Procedures

### When Things Go Wrong

#### Build Broken
1. Revert to last known good state
2. Fix forward with tests
3. Document root cause

#### Performance Regression
1. Profile immediately
2. Bisect to find cause
3. Fix or revert
4. Add performance test

#### Security Issue
1. STOP all other work
2. Assess severity
3. Fix immediately
4. Responsible disclosure if needed

---

## Quality Gates

### Before Merging Any Code
- [ ] All tests pass
- [ ] No decrease in coverage
- [ ] No performance regression
- [ ] No new warnings
- [ ] Documentation updated
- [ ] CHANGELOG entry added

### Before Any Release
- [ ] Full test suite passes
- [ ] Benchmarks meet targets
- [ ] Security scan clean
- [ ] Documentation complete
- [ ] Upgrade path tested
- [ ] Rollback plan ready

---

## Long-Term Vision

### Year 1: Foundation
- Full Cardano compatibility
- Performance leadership
- Growing community

### Year 2: Innovation  
- Unique features beyond reference
- Enterprise deployments
- Ecosystem integrations

### Year 3: Standard
- Preferred node implementation
- Teaching platform
- Research contributions

---

## Our Promise

We are building Kassadin to be:
1. **Reliable**: It works correctly, always
2. **Performant**: It's faster than alternatives  
3. **Usable**: Anyone can run it successfully
4. **Maintainable**: Code is clean and clear
5. **Valuable**: It serves real user needs

We will not compromise these values for expediency.

---

## Session Commands

Commands to run at various points:

### Start of Session
```bash
# Check environment
zig version
git status
zig build test

# Review todos
cat TODO.md  # If we maintain one separately
```

### Before Committing
```bash
# Format code
zig fmt src/

# Run all tests
zig build test

# Check for issues
zig build check
```

### End of Session
```bash
# Commit work
git add -A
git commit -m "Descriptive message"

# Update documentation
# Update progress in KASSADIN_DEVELOPMENT_PLAN.md

# Note any decisions made
# Update this file if needed
```

### Progress Recording Protocol

At each milestone or significant checkpoint:

1. **Update Development Plan**
   - Mark completed tasks with [x]
   - Update metrics (LOC, test coverage, etc.)
   - Add session notes to Weekly Log
   - Record any deviations from plan

2. **Document Learnings**
   ```markdown
   #### Session: [Date]
   **Completed**:
   - Task 1 with outcome
   - Task 2 with outcome
   
   **Challenges**:
   - Issue encountered and solution
   
   **Decisions**:
   - Decision made and rationale
   
   **Next Steps**:
   - Immediate next task
   ```

3. **Update Metrics**
   - Lines of Code
   - Test Coverage
   - Tests Passing
   - Performance Benchmarks

4. **Risk Assessment**
   - New risks identified
   - Mitigation strategies updated
   - Timeline adjustments if needed

---

## Contact & Escalation

### For AI Assistant
- If blocked > 15 minutes: Stop and discuss
- If design decision needed: Present options
- If specification unclear: Research and propose
- If approach uncertain: Implement spike and review

### For Human Developer  
- Architecture decisions: Final authority
- External dependencies: Approval required
- API changes: Review needed
- Performance trade-offs: Joint decision

---

*This document defines our working relationship and standards. It is a living document and should be updated as we learn and grow.*

*Last Updated: [Session Date]*
*Version: 1.0.0*