package com.distrimind.util.export;

import java.io.File;
import java.util.ArrayList;

import javax.lang.model.SourceVersion;

import com.distrimind.util.properties.XMLProperties;

public class Exports extends XMLProperties
{
    /**
     * 
     */
    private static final long serialVersionUID = 2428443980388438163L;

    private JavaProjectDependency project;
    private File temporaryDirectory=null;
    private File exportDirectory=null;
    private String ftpUrl=null;
    private int ftpPort=0;
    private ArrayList<ExportProperties> exportsSenarios=null;
    private SourceVersion javaVersion;
    


    
    public SourceVersion getJavaVersion()
    {
        return javaVersion;
    }

    public void setJavaVersion(SourceVersion _javaVersion)
    {
        javaVersion = _javaVersion;
    }

    public JavaProjectDependency getProject()
    {
        return project;
    }

    public void setProject(JavaProjectDependency _project)
    {
        project = _project;
    }

    public Exports()
    {
	super(null);
    }

    public void export() throws Exception
    {
	project.getVersion().loadBuildNumber(getBuildFile());
	project.getVersion().incrementBuildNumber();
	project.getVersion().saveBuildNumber(getBuildFile());
	
	for (ExportProperties ep : exportsSenarios)
	{
	    Export e=new Export(this, ep);
	    e.export();
	}
    }
    
    
    public File getBuildFile()
    {
        return project.getBuildFilePath(((JavaProjectSourceDependency)project.getSourceCode()).getSourceDirectory());
    }

    
    
    public File getTemporaryDirectory()
    {
        return temporaryDirectory;
    }

    public void setTemporaryDirectory(File _temporaryDirectory)
    {
        temporaryDirectory = _temporaryDirectory;
    }

    public File getExportDirectory()
    {
        return exportDirectory;
    }

    public void setExportDirectory(File _exportDirectory)
    {
        exportDirectory = _exportDirectory;
    }


    public String getFtpUrl()
    {
        return ftpUrl;
    }

    public void setFtpUrl(String _ftpUrl)
    {
        ftpUrl = _ftpUrl;
    }

    public int getFtpPort()
    {
        return ftpPort;
    }

    public void setFtpPort(int _ftpPort)
    {
        ftpPort = _ftpPort;
    }


    public ArrayList<ExportProperties> getExportsSenarios()
    {
        return exportsSenarios;
    }

    public void setExportsSenarios(ArrayList<ExportProperties> _exportsSenarios)
    {
        exportsSenarios = _exportsSenarios;
    }



    public static class ExportProperties extends XMLProperties
    {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7312414086912484454L;
	
	public final boolean include_dependancies;
	public final SourceCodeExportType source_code_export_type;
	public final boolean include_documentation;
	
	public ExportProperties(boolean _include_dependancies, SourceCodeExportType _source_code_export_type, boolean _include_documentation)
	{
	    super(null);
	    include_dependancies=_include_dependancies;
	    source_code_export_type=_source_code_export_type;
	    include_documentation=_include_documentation;
	}
	
    }
    
    public static enum SourceCodeExportType
    {
	NO_SOURCE_CODE,
	SOURCE_CODE_IN_SEPERATE_FILE,
	SOURCE_CODE_IN_JAR_FILE
    }

}
