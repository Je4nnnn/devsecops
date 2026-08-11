import com.cloudbees.plugins.credentials.CredentialsScope
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import com.cloudbees.plugins.credentials.domains.Domain
import hudson.plugins.git.BranchSpec
import hudson.plugins.git.GitSCM
import hudson.plugins.git.UserRemoteConfig
import hudson.plugins.sonar.SonarGlobalConfiguration
import hudson.plugins.sonar.SonarInstallation
import hudson.plugins.sonar.model.TriggersConfig
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import hudson.util.Secret
import jenkins.install.InstallState
import jenkins.model.Jenkins
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl
import org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def env = System.getenv()
def jenkins = Jenkins.get()
def setupMarker = new File(jenkins.rootDir, ".devsecops-local-jenkins-setup")

def adminUser = env.get("JENKINS_ADMIN_ID") ?: "admin"
def adminPassword = env.get("JENKINS_ADMIN_PASSWORD")
if (!adminPassword?.trim()) {
    def initialPasswordFile = new File(jenkins.rootDir, "secrets/initialAdminPassword")
    adminPassword = initialPasswordFile.exists() ? initialPasswordFile.text.trim() : UUID.randomUUID().toString()
}

if (!setupMarker.exists()) {
    def securityRealm = new HudsonPrivateSecurityRealm(false)
    securityRealm.createAccount(adminUser, adminPassword)
    jenkins.setSecurityRealm(securityRealm)

    def authorizationStrategy = new FullControlOnceLoggedInAuthorizationStrategy()
    authorizationStrategy.setAllowAnonymousRead(false)
    jenkins.setAuthorizationStrategy(authorizationStrategy)

    setupMarker.text = "Configured by dev-tools/jenkins/init.groovy.d on ${new Date()}\n"
    println("DevSecOps local Jenkins admin user configured: ${adminUser}")
}

try {
    jenkins.setInstallState(InstallState.INITIAL_SETUP_COMPLETED)
} catch (Throwable ignored) {
    InstallState.INITIAL_SETUP_COMPLETED.initializeState()
}

def credentialsProvider = SystemCredentialsProvider.getInstance()
def sonarTokenId = env.get("SONAR_TOKEN_CREDENTIAL_ID") ?: "sonar-token"
def sonarToken = env.get("SONAR_TOKEN") ?: "replace-with-real-sonarqube-token"
def sonarCredentialExists = credentialsProvider.getCredentials().any { it.id == sonarTokenId }
if (!sonarCredentialExists) {
    credentialsProvider.getCredentials().add(
        new StringCredentialsImpl(
            CredentialsScope.GLOBAL,
            sonarTokenId,
            "Token de SonarQube para el pipeline DevSecOps",
            Secret.fromString(sonarToken)
        )
    )
    credentialsProvider.save()
    println("DevSecOps local Jenkins credential configured: ${sonarTokenId}")
}

def sonarConfig = SonarGlobalConfiguration.get()
def sonarInstallations = sonarConfig.getInstallations() as List
def sonarExists = sonarInstallations.any { it.name == "sonarqube" }
if (!sonarExists) {
    sonarInstallations.add(
        new SonarInstallation(
            "sonarqube",
            "http://sonarqube:9000",
            sonarTokenId,
            "",
            "",
            new TriggersConfig(),
            ""
        )
    )
    sonarConfig.setInstallations(sonarInstallations as SonarInstallation[])
    sonarConfig.save()
    println("DevSecOps local Jenkins SonarQube server configured: sonarqube")
}

def jobName = env.get("PIPELINE_JOB_NAME") ?: "devsecops-pipeline"
def gitUrl = env.get("PIPELINE_GIT_URL") ?: "https://github.com/Je4nnnn/devsecops"
def gitBranch = env.get("PIPELINE_GIT_BRANCH") ?: "*/codex/entrega3-portable-qa"
def scriptPath = env.get("PIPELINE_SCRIPT_PATH") ?: "dev-tools/jenkins/Jenkinsfile"

def job = jenkins.getItem(jobName)
if (job == null) {
    job = jenkins.createProject(WorkflowJob.class, jobName)
    println("DevSecOps local Jenkins pipeline job created: ${jobName}")
}

def remote = new UserRemoteConfig(gitUrl, null, null, null)
def scm = new GitSCM(
    [remote],
    [new BranchSpec(gitBranch)],
    false,
    [],
    null,
    null,
    []
)
def definition = new CpsScmFlowDefinition(scm, scriptPath)
definition.setLightweight(true)
job.setDefinition(definition)
job.setDescription("Pipeline DevSecOps local desde ${gitUrl}, branch ${gitBranch}, Jenkinsfile ${scriptPath}.")
job.save()

jenkins.save()
