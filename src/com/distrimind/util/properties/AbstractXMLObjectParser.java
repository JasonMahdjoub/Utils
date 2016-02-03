/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */

package com.distrimind.util.properties;

/**
 * This object enables to convert an object to XML node content, and conversely.
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public abstract class AbstractXMLObjectParser
{
    /**
     * Convert the XML node content to an object
     * @param field_type the object type
     * @param nodeValue the XML node content
     * @return the corresponding object
     * @throws Exception if a problem occurs
     */
    public abstract Object convertXMLToObject(Class<?> field_type, String nodeValue) throws Exception;
    
    /**
     * Convert an object to a XML node content
     * @param field_type the object type
     * @param object the object to convert
     * @return the XML node content
     * @throws Exception if a problem occurs
     */
    public abstract String convertObjectToXML(Class<?> field_type, Object object) throws Exception;
    
}
