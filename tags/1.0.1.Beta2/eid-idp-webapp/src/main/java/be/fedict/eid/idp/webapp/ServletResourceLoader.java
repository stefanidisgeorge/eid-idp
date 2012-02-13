package be.fedict.eid.idp.webapp;

import com.sun.xml.ws.transport.http.ResourceLoader;

import javax.servlet.ServletContext;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

final class ServletResourceLoader implements ResourceLoader {
	private final ServletContext context;

	public ServletResourceLoader(ServletContext context) {
		this.context = context;
	}

	public URL getResource(String path) throws MalformedURLException {
		return context.getResource(path);
	}

	public URL getCatalogFile() throws MalformedURLException {
		return getResource("/WEB-INF/jax-ws-catalog.xml");
	}

	public Set<String> getResourcePaths(String path) {
		return context.getResourcePaths(path);
	}
}
