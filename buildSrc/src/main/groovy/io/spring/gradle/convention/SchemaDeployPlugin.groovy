package io.spring.gradle.convention

import org.gradle.api.Plugin
import org.gradle.api.Project

public class SchemaDeployPlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		project.getPluginManager().apply('org.hidetake.ssh')

		project.ssh.settings {
			knownHosts = allowAnyHosts
		}
		project.remotes {
			docs {
				role 'docs'
				if (project.hasProperty('deployDocsHost')) {
					host = project.findProperty('deployDocsHost')
				} else {
					host = 'docs.af.pivotal.io'
				}
				retryCount = 5 // retry 5 times (default is 0)
				retryWaitSec = 10 // wait 10 seconds between retries (default is 0)
				user = project.findProperty('deployDocsSshUsername')
				if(project.hasProperty('deployDocsSshKeyPath')) {
					identity = project.file(project.findProperty('deployDocsSshKeyPath'))
				} else if (project.hasProperty('deployDocsSshKey')) {
					identity = project.findProperty('deployDocsSshKey')
				}
				if(project.hasProperty('deployDocsSshPassphrase')) {
					passphrase = project.findProperty('deployDocsSshPassphrase')
				}
			}
		}

		project.task('deploySchema') {
			dependsOn 'schemaZip'
			doFirst {
				project.ssh.run {
					session(project.remotes.docs) {
						def now = System.currentTimeMillis()
						def name = project.rootProject.name
						def version = project.rootProject.version
						def tempPath = "/tmp/${name}-${now}-schema/".replaceAll(' ', '_')

						execute "mkdir -p $tempPath"

						project.tasks.schemaZip.outputs.each { o ->
							println "Putting $o.files"
							put from: o.files, into: tempPath
						}

						execute "unzip $tempPath*.zip -d $tempPath"

						def extractPath = "/var/www/domains/spring.io/docs/htdocs/autorepo/schema/${name}/${version}/"

						execute "rm -rf $extractPath"
						execute "mkdir -p $extractPath"
						execute "rm -f $tempPath*.zip"
						execute "rm -rf $extractPath*"
						execute "mv $tempPath/* $extractPath"

						/*
						 * Symlink spring-security schema so that legacy projects using the "http" scheme can
						 * resolve the following schema location:
						 *
						 * - http://www.springframework.org/schema/security/spring-security.xsd
						 *
						 * Copy spring-security-oauth schemas so that legacy projects using the "http" scheme can
						 * resolve the following schema locations:
						 *
						 * - http://www.springframework.org/schema/security/spring-security-oauth-1.0.xsd
						 * - http://www.springframework.org/schema/security/spring-security-oauth2-1.0.xsd
						 * - http://www.springframework.org/schema/security/spring-security-oauth2-2.0.xsd
						 *
						 * Note: The directory:
						 *   https://www.springframework.org/schema/security/
						 *
						 * is a symbolic link pointing to:
						 *   https://docs.spring.io/autorepo/schema/spring-security/current/security/
						 *
						 * which in turn points to the latest:
						 *   https://docs.spring.io/autorepo/schema/spring-security/$version/security/
						 *
						 * with the help of the autoln command which is run regularly via a cron job.
						 *
						 * See https://github.com/spring-io/autoln for more info.
						 */
						if (name == "spring-security") {
							def versionString = project.rootProject.version.toString()
							versionString = versionString.substring(0, versionString.lastIndexOf('.'))
							execute "ln -sfd ${extractPath}security/${name}-${versionString}.xsd ${name}.xsd"
							def springSecurityOauthPath = "/var/www/domains/spring.io/docs/htdocs/autorepo/schema/spring-security-oauth/current/security"
							execute "cp $springSecurityOauthPath/* ${extractPath}security"
						}

						execute "chmod -R g+w $extractPath"
					}
				}
			}
		}
	}
}
