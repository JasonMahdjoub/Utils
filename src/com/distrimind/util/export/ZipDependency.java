/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */
public class ZipDependency extends BinaryDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = -6230684853876461834L;

    private File jar_dependency;

    public ZipDependency()
    {

    }

    public ZipDependency(String name, Package _subpackage, License licenses[], File jar_file_dependency)
    {
	this(name, new ZipSourceDependancy(false, jar_file_dependency,
		getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex()),
		_subpackage, licenses, jar_file_dependency,
		getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }

    public ZipDependency(String name, SourceDependancy source_code, Package _subpackage, License[] licenses, File jar_file_dependency, String _exclude_regex, String _include_regex)
    {
	super(name, source_code, _subpackage, licenses, _exclude_regex,
		_include_regex);
	if (jar_file_dependency == null)
	    throw new NullPointerException("jar_file_dependency");
	if (!jar_file_dependency.exists())
	    throw new IllegalArgumentException(
		    "The given file does not exists : " + jar_file_dependency);
	if (!jar_file_dependency.isFile())
	    throw new IllegalArgumentException(
		    "The given file is not a file : " + jar_file_dependency);
	jar_dependency = jar_file_dependency;
    }

    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.unzipFile(jar_dependency, _folder, exclude_regex,
		include_regex);
    }

    @Override
    String getAntSetFile()
    {
	return "<fileset file=\"" + jar_dependency.getAbsolutePath()
		+ "\"></fileset>";
    }

    @Override
    String getClassPath()
    {
	return jar_dependency.getAbsolutePath();
    }

    public File getFile()
    {
	return jar_dependency;
    }

}
