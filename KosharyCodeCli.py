import sys
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph
from typing import TypedDict, List

llm = ChatOpenAI(
    model="gpt-4o",
    temperature=0,
    max_tokens=None,
    timeout=None,
    max_retries=2,
    api_key="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"
)

# llm = ChatGroq(
#     temperature=0, 
#     max_tokens=8000,
#     model_name="llama-3.3-70b-versatile",
#     api_key="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"
#     )

# Define the graph state type
class GraphState(TypedDict):
    """
    Represents the state of our graph.
    """
    context: str
    code: str
    messages: List[str]
    vulnerabilities: List[str]

# Define the code review graph
def code_review_graph():

    def analysis_node(state: GraphState):
        print("------ Starting code analysis phase -------")
        prompt = f"""You are an expert code analyzer tasked with understanding and categorizing code snippets. For the given code, provide a detailed analysis in a strict JSON format.

          ```
          {state['code']}
          ```

          Detailed Analysis Instructions:
            1. Carefully examine the entire code snippet
            2. Identify key components, functions, and logical structures
            3. Determine the high-level goal of the code
            4. Explain any non-obvious or complex parts of the implementation
            5. Note any significant algorithms or design patterns used

            Output Template:
            {{
                "language": "[Specific programming language name]",
                "framework": "[Specific framework or library name, or 'None' if not applicable]",
                "primary_purpose": "[Clear, concise description of the code's core functionality]",
                "code_insights": {{
                    "key_functions": ["list of primary functions"],
                    "potential_use_cases": ["list of scenarios where this code might be applied"]
                }}
            }}

            Requirements:
            - Be precise and specific in your categorization
            - Use industry-standard terminology
            - Ensure the JSON is valid and properly formatted
            - If a field cannot be determined, use null or an empty string
        """
        response = llm.invoke([HumanMessage(content=prompt)])
        print(response.content)
        state['context'] = response.content
        return state

    def data_flow_node(state: GraphState):
        print("------ Analyzing function inputs -------")
        prompt = f"""You are an expert code analyzer tasked with understanding the general data flow in code snippets. For the given code, examine every function for its input and output. Identify where the output is used, where it gets its input from, and if it interacts with other functions. Provide a detailed analysis in a strict JSON format.

          ```
          {state['code']}
          ```
          Context: {state['context']}

          Detailed Analysis Instructions:
            1. Carefully examine the functions in the code snippet and their inputs/outputs.
            2. Consider all possible inputs, including edge cases like too large, too small, or unexpected data types.
            3. Determine where each function gets its input from and where it interacts with other functions.
            4. Determine where each function's output is reflected.

            Output Template:
            {{
                "input_analysis": {{ 
                    "function_one_name": {{
                        "input_one": "[input usage]",
                        "output_one": "[where it is reflected]",
                        "functions_interaction": "[what functions does it interact with]"
                    }},
                    "function_two_name": {{
                        "input_one": "[input usage]",
                        "output_one": "[where it is reflected]",
                        "functions_interaction": "[what functions does it interact with]"
                    }}
                }},
                "general_data_flow": {{
                    "step1": ["...."],
                    "step2": ["...."]
                }},
                "noticed_behaviour_for_unexpected_inputs": {{
                    "behaviour1": ["note that this section might not always exist"]
                }}
            }}
        """
        response = llm.invoke([HumanMessage(content=prompt)])
        print(response.content)
        state['context'] += response.content
        return state


    def security_review_node(state: GraphState):
      print("------ Reviewing code security -------")
      prompt = f""" ## Primary Objective
      You are a highly skilled security code reviewer specialized in identifying vulnerabilities,
      You will be given a piece of code along with some context to do a securety code review,

      Detailed  Instructions:
      1. Carefully examine the functions in the code snippet and their inputs/outputs , data flow , reflected output etc.
      2. Determine the potential security context and threat landscape
      3. Determine where each function gets its input from and where it interacts with other functions.
      4. For each function in the input you must check for vulenrabelites , examples :

      #### A. Authentication and Access Control
      - Analyze authentication mechanisms
      - Inspect authorization checks
      - Verify proper implementation of role-based access control (RBAC)
      - Check for potential privilege escalation vulnerabilities

      #### B. Input Validation and Sanitization
      - Examine all input handling procedures
      - Identify potential injection points (SQL, OS, LDAP, XPath)
      - Assess sanitization and validation strategies
      - Detect potential cross-site scripting (XSS) risks

      #### C. Data Protection
      - Review encryption implementations
      - Analyze sensitive data handling
      - Check for secure storage of credentials and tokens
      - Evaluate protection against data exposure

      #### D. Error Handling and Logging
      - Inspect error handling mechanisms
      - Verify no sensitive information is exposed in error messages
      - Assess logging practices for security events
      - Check for potential information disclosure risks

      #### E. Communication Security
      - Analyze network communication protocols
      - Review SSL/TLS implementation
      - Check for secure communication practices
      - Identify potential man-in-the-middle vulnerability risks

      #### F. Dependency and Library Security
      - Scan third-party libraries and dependencies
      - Check for known vulnerabilities in used packages
      - Assess version currency and patch levels
      - Evaluate potential supply chain security risks


      For each identified potential vulnerability:
      1. Describe the specific security weakness
      2. Explain the potential exploitation mechanism
      3. Provide a risk rating (Critical/High/Medium/Low)
      4. Recommend concrete remediation strategies
      




      ### Critical
      - You must note that not every security issue is a vulnerability some might be given as a general recommendation
      - Not every code you are provided with is vulnerable
      - Output Template:
            {{
                "Vulnerability_one_name": {{ 
                    "function_name": {{
                        "[Vulnerability detailes]"
                    }},
                    "sevirety": {{
                        "[Sevirety detailes]"
                    }},
                "general_reccomendation: {{
                    "reccomendation1": ["...."],
                    "reccomendation2": ["...."]
                   }},
                "noticed_behaviour": {{
                    "behaviour1": ["note that this section might not always exist"]
                  }},
                }},
            }}

        code to review : {state['code']}
        context : {state['context']}


      """

      response = llm.invoke([HumanMessage(content=prompt)])
      print(response.content)
      state['vulnerabilities'] += response.content
      return state

    # def reporting_node(state: GraphState):
    #   prompt = """ ## Primary Objective
    #   You are a highly skilled security code reviewer specialized in identifying vulnerabilities, analyzing code quality, and providing actionable recommendations for improving code security across multiple programming languages and frameworks.
    #   """



    # Define the workflow graph
    workflow = StateGraph(GraphState)
    workflow.add_node("code_understanding", analysis_node)
    workflow.add_node("data_flow_understanding", data_flow_node)
    workflow.add_node("security_review",security_review_node )

    workflow.set_entry_point("code_understanding")
    workflow.add_edge("code_understanding", "data_flow_understanding")
    workflow.add_edge("data_flow_understanding", "security_review")
    return workflow.compile()

# Main function to run the graph
def analyze_code(code: str):
    """Main function to run the code analysis"""
    graph = code_review_graph()
    initial_state = GraphState(context="", code=code, messages=[], vulnerabilities=[])
    
    # Run the graph
    result = graph.invoke(initial_state)
    return result



def analyze_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            print(f"Analyzing {file_path}...")
            analyze_code(content)
            result = f"Review results for {file_path}: Done ! "  # Mock result
            print(result)
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
# input_code = """
# <?php
#
# if( isset( $_GET[ 'Change' ] ) ) {
# 	// Checks to see where the request came from
# 	if( stripos( $_SERVER[ 'HTTP_REFERER' ] ,$_SERVER[ 'SERVER_NAME' ]) !== false ) {
# 		// Get input
# 		$pass_new  = $_GET[ 'password_new' ];
# 		$pass_conf = $_GET[ 'password_conf' ];
#
# 		// Do the passwords match?
# 		if( $pass_new == $pass_conf ) {
# 			// They do!
# 			$pass_new = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $pass_new ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
# 			$pass_new = md5( $pass_new );
#
# 			// Update the database
# 			$current_user = dvwaCurrentUser();
# 			$insert = "UPDATE `users` SET password = '$pass_new' WHERE user = '" . $current_user . "';";
# 			$result = mysqli_query($GLOBALS["___mysqli_ston"],  $insert ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
#
# 			// Feedback for the user
# 			$html .= "<pre>Password Changed.</pre>";
# 		}
# 		else {
# 			// Issue with passwords matching
# 			$html .= "<pre>Passwords did not match.</pre>";
# 		}
# 	}
# 	else {
# 		// Didn't come from a trusted source
# 		$html .= "<pre>That request didn't look correct.</pre>";
# 	}
#
# 	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
# }
#
# ?>
# """


def main():
    if len(sys.argv) < 2:
        print("No files provided for analysis.")
        sys.exit(1)

    files_to_analyze = sys.argv[1:]
    for file_path in files_to_analyze:
        analyze_file(file_path)


if __name__ == "__main__":
    main()


