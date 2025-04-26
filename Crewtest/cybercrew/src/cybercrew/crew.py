from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from dotenv import load_dotenv
from src.cybercrew.tools.custom_tool import NetworkScanTool, VulnAnalysisTool, ExploitTool, WhoisLookupTool, SubdomainEnumerationTool, CVELookupTool, ExploitDBSearchTool, ExploitTool, PostgreSQLExploitTool, RDPExploitTool, NcrackTool, MetasploitExploitTool, CMEExploitationTool, SMBVulnScannerTool, EternalBlueExploitTool, MeterpreterPostExploitTool, PostExploitTool, LogCleanerTool, ReportGeneratorTool
# Load environment variables from .env file
load_dotenv()

scan_tool = NetworkScanTool()
vuln_tool = VulnAnalysisTool()
exploit_tool = ExploitTool()
whois_tool = WhoisLookupTool()
subdomain_tool = SubdomainEnumerationTool()
cve_tool = CVELookupTool()
exploit_db_tool = ExploitDBSearchTool()
exploitation_simulator_tool = ExploitTool()
post_exploitation_tool = PostExploitTool()
log_cleaner_tool = LogCleanerTool()
Report_Generator_Tool = ReportGeneratorTool()
SQLExploitTool = PostgreSQLExploitTool()
RDP_ExploitTool = RDPExploitTool()
Ncrack_Tool = NcrackTool()
CME_ExploitTool = CMEExploitationTool()
Metas_ExploitTool = MetasploitExploitTool()
SMB_VulnScannerTool = SMBVulnScannerTool()
EternalBlue_ExploitTool = EternalBlueExploitTool()
Meter_preterPost_ExploitTool = MeterpreterPostExploitTool()


# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class Cybercrew():
    """Cybercrew crew""" 

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def recon_agent(self) -> Agent:
        return Agent(
            config=self.agents_config["recon_agent"],
            tools=[scan_tool, whois_tool, subdomain_tool],
            verbose=True
        )
    
    # Deuxième agent : Agent de balayage
    @agent
    def scanner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['scanner_agent'],
            tools=[scan_tool, SMB_VulnScannerTool, vuln_tool],
            verbose=True
        )
    
    @agent
    def vuln_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['vuln_agent'],
            tools=[vuln_tool, cve_tool, exploit_db_tool],
            verbose=True
        )
    
    @agent
    def exploit_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['exploit_agent'],
            tools=[exploit_tool, exploitation_simulator_tool, SQLExploitTool, RDP_ExploitTool, Ncrack_Tool, CME_ExploitTool, Metas_ExploitTool, EternalBlue_ExploitTool, SMB_VulnScannerTool, Meter_preterPost_ExploitTool],
            verbose=True
        )

    @agent
    def post_exploitation_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['post_exploitation_agent'],
            tools=[post_exploitation_tool, log_cleaner_tool, Meter_preterPost_ExploitTool],
            verbose=True
    )

    @agent
    def report_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['report_agent'],
            tools=[Report_Generator_Tool],
            verbose=True
        )

    @task
    def recon_task(self) -> Task:
        return Task(
            config=self.tasks_config["recon_task"]
        )
    
    @task
    def scan_task(self) -> Task:
        return Task(
            config=self.tasks_config['scan_task'],
        )
    
    @task
    def vuln_test_task(self) -> Task:
        return Task(
            config=self.tasks_config['vuln_task'],
        )

    @task
    def exploit_task(self) -> Task:
        return Task(
            config=self.tasks_config['exploit_task'],
        )
    
    @task
    def post_exploit_task(self) -> Task:
        return Task(
            config=self.tasks_config['post_exploit_task'],
        )
    
    @task
    def report_task(self) -> Task:
        return Task(
            config=self.tasks_config['report_task'],
        )
    
    @crew
    def crew(self) -> Crew:
        """Creates the Cybercrew crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )
